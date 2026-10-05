//! Best-effort generic Apple notifications. Never a command or decision transport.
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use syn_config::APNSConfig;
use syn_protocol::NotificationRegistrationV1;
use tokio::sync::{mpsc, Mutex};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination {
    token: String,
    environment: String,
}

pub struct Notifications {
    config: APNSConfig,
    destinations: Arc<Mutex<BTreeMap<String, Destination>>>,
    queue: mpsc::Sender<u64>,
}
impl Notifications {
    pub fn start(config: APNSConfig, allowed_devices: &[String]) -> Result<Self> {
        config.validate()?;
        let metadata =
            fs::symlink_metadata(&config.signing_key).context("Apple push key is unavailable")?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o027 != 0 {
            bail!("Apple push key permissions are unsafe");
        }
        let pem = Zeroizing::new(
            fs::read_to_string(&config.signing_key).context("Apple push key is unreadable")?,
        );
        let signing_key = SigningKey::from_pkcs8_pem(&pem)
            .map_err(|_| anyhow::anyhow!("invalid Apple push signing key"))?;
        let mut destinations = read_destinations(&config.state_file)?;
        destinations.retain(|id, dest| {
            allowed_devices.contains(id) && dest.environment == config.environment
        });
        let destinations = Arc::new(Mutex::new(destinations));
        let (queue, mut receiver) = mpsc::channel::<u64>(64);
        let worker_destinations = destinations.clone();
        let worker_config = config.clone();
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()?;
        tokio::spawn(async move {
            let mut cached_authorization: Option<(u64, String)> = None;
            while let Some(expiry) = receiver.recv().await {
                let now = unix_seconds();
                if expiry <= now {
                    continue;
                }
                let destinations = worker_destinations.lock().await.clone();
                if cached_authorization.as_ref().is_none_or(|(issued, _)| {
                    now < *issued || now.saturating_sub(*issued) >= 45 * 60
                }) {
                    cached_authorization =
                        Some((now, provider_token(&worker_config, &signing_key, now)));
                }
                let authorization = &cached_authorization
                    .as_ref()
                    .expect("provider token generated")
                    .1;
                for (device, destination) in destinations {
                    if expiry <= unix_seconds() {
                        break;
                    }
                    let host = if worker_config.environment == "development" {
                        "api.sandbox.push.apple.com"
                    } else {
                        "api.push.apple.com"
                    };
                    let response = client
                        .post(format!("https://{host}/3/device/{}", destination.token))
                        .bearer_auth(authorization)
                        .header("apns-topic", &worker_config.topic)
                        .header("apns-push-type", "alert")
                        .header("apns-priority", "10")
                        .header("apns-expiration", expiry.to_string())
                        .json(&generic_payload())
                        .send()
                        .await;
                    match response {
                        Ok(reply) if reply.status().is_success() => {}
                        Ok(reply) if reply.status() == reqwest::StatusCode::GONE => {
                            worker_destinations.lock().await.remove(&device);
                            // No credential, token, response body or URL is logged.
                            tracing::warn!("Apple notification destination expired");
                        }
                        _ => tracing::warn!("Apple notification was not delivered to APNs"),
                    }
                }
            }
        });
        Ok(Self {
            config,
            destinations,
            queue,
        })
    }
    pub async fn register(
        &self,
        device: &str,
        registration: NotificationRegistrationV1,
    ) -> Result<()> {
        registration.validate()?;
        if registration.environment != self.config.environment {
            bail!("notification environment mismatch");
        }
        let destination = Destination {
            token: hex::encode(registration.token.as_slice()),
            environment: registration.environment,
        };
        let mut values = self.destinations.lock().await;
        values.insert(device.into(), destination);
        write_destinations(&self.config.state_file, &values)?;
        Ok(())
    }
    pub fn notify(&self, expiry: u64) {
        if self.queue.try_send(expiry).is_err() {
            tracing::warn!("Apple notification queue is full");
        }
    }
}
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn provider_token(config: &APNSConfig, key: &SigningKey, now: u64) -> String {
    let header =
        URL_SAFE_NO_PAD.encode(serde_json::json!({"alg":"ES256", "kid":config.key_id}).to_string());
    let payload =
        URL_SAFE_NO_PAD.encode(serde_json::json!({"iss":config.team_id, "iat":now}).to_string());
    let input = format!("{header}.{payload}");
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}
fn generic_payload() -> serde_json::Value {
    serde_json::json!({"aps":{"alert":{"title":"Syn approval requested", "body":"Open Syn to review a pending request."},"sound":"default"}})
}
fn read_destinations(path: &Path) -> Result<BTreeMap<String, Destination>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(_) => bail!("unable to inspect Apple notification state"),
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || metadata.len() > 64 * 1024
            {
                bail!("Apple notification state permissions are unsafe");
            }
            let values: BTreeMap<String, Destination> = serde_json::from_slice(&fs::read(path)?)
                .map_err(|_| anyhow::anyhow!("invalid Apple notification state"))?;
            if values.len() > 8
                || values.values().any(|v| {
                    v.token.is_empty()
                        || v.token.len() > 512
                        || !v.token.bytes().all(|b| b.is_ascii_hexdigit())
                })
            {
                bail!("invalid Apple notification destinations");
            }
            Ok(values)
        }
    }
}
fn write_destinations(path: &Path, values: &BTreeMap<String, Destination>) -> Result<()> {
    let parent = path
        .parent()
        .context("missing Apple notification state parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("unsafe Apple notification state parent");
    }
    let temporary = path.with_extension("new");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(&serde_json::to_vec(values)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn alert_contains_no_remote_metadata() {
        assert_eq!(generic_payload().as_object().unwrap().len(), 1);
        assert!(generic_payload()["aps"]["alert"]["body"]
            .as_str()
            .unwrap()
            .contains("Open Syn"));
        assert!(generic_payload().get("request_id").is_none());
    }
    #[test]
    fn token_has_a_valid_provider_signature() {
        use p256::ecdsa::signature::Verifier;
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let config = APNSConfig {
            team_id: "ABCDEFGHIJ".into(),
            key_id: "KLMNOPQRST".into(),
            topic: "org.syn-approvals.SynIOS.Debug".into(),
            environment: "development".into(),
            signing_key: "/unused".into(),
            state_file: "/unused-state".into(),
        };
        let token = provider_token(&config, &key, 1234);
        let (input, signature) = token.rsplit_once('.').unwrap();
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
        assert!(key
            .verifying_key()
            .verify(input.as_bytes(), &signature)
            .is_ok());
    }
}
