//! Public approver enrollment. A TLS identity and its decision keys form one immutable record.
use crate::ConfigError;
use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApproverRecord {
    pub schema_version: u16,
    pub device_id: String,
    pub display_name: String,
    pub development: bool,
    pub approval_public_x963_base64: String,
    pub denial_public_x963_base64: String,
    pub client_certificate_pem: String,
}

impl ApproverRecord {
    pub fn keys(&self) -> Result<(VerifyingKey, VerifyingKey), ConfigError> {
        let parse = |s: &str| -> Result<VerifyingKey, ConfigError> {
            let bytes = STANDARD.decode(s).map_err(|_| invalid())?;
            if bytes.len() != 65 {
                return Err(invalid());
            }
            VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| invalid())
        };
        Ok((
            parse(&self.approval_public_x963_base64)?,
            parse(&self.denial_public_x963_base64)?,
        ))
    }
    pub fn certificate_der(&self) -> Result<Vec<u8>, ConfigError> {
        let text = self.client_certificate_pem.trim();
        if text.len() > 16 * 1024 {
            return Err(invalid());
        }
        let body = text
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .and_then(|s| s.strip_suffix("-----END CERTIFICATE-----"))
            .ok_or_else(invalid)?;
        let der = STANDARD
            .decode(body.split_whitespace().collect::<String>())
            .map_err(|_| invalid())?;
        if der.is_empty() || der.len() > 12 * 1024 {
            return Err(invalid());
        }
        Ok(der)
    }
    pub fn certificate_fingerprint(&self) -> Result<[u8; 32], ConfigError> {
        Ok(Sha256::digest(self.certificate_der()?).into())
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1
            || self.device_id.is_empty()
            || self.device_id.len() > 64
            || !self
                .device_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || self.display_name.is_empty()
            || self.display_name.len() > 128
            || self.display_name.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        let (approval, denial) = self.keys()?;
        if approval == denial {
            return Err(invalid());
        }
        self.certificate_der()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproverRegistry {
    pub schema_version: u16,
    pub approvers: Vec<ApproverRecord>,
}
impl ApproverRegistry {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            approvers: vec![],
        }
    }
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(invalid());
            }
        }
        if metadata.len() > 128 * 1024 {
            return Err(invalid());
        }
        let data = fs::read(path).map_err(|_| invalid())?;
        let registry: Self = serde_json::from_slice(&data).map_err(|_| invalid())?;
        registry.validate()?;
        Ok(registry)
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 || self.approvers.len() > 8 {
            return Err(invalid());
        }
        let mut ids = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut certificates = BTreeSet::new();
        for record in &self.approvers {
            record.validate()?;
            let (approval, denial) = record.keys()?;
            if !ids.insert(&record.device_id)
                || !keys.insert(syn_protocol::key_id(&approval))
                || !keys.insert(syn_protocol::key_id(&denial))
                || !certificates.insert(record.certificate_fingerprint()?)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}
fn invalid() -> ConfigError {
    ConfigError::Invalid("invalid or unsafe approver registry".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(id: &str) -> ApproverRecord {
        let approval = p256::ecdsa::SigningKey::from_slice(&[2; 32]).unwrap();
        let denial = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        ApproverRecord {
            schema_version: 1,
            device_id: id.into(),
            display_name: "Test phone".into(),
            development: true,
            approval_public_x963_base64: STANDARD
                .encode(approval.verifying_key().to_encoded_point(false).as_bytes()),
            denial_public_x963_base64: STANDARD
                .encode(denial.verifying_key().to_encoded_point(false).as_bytes()),
            client_certificate_pem:
                "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----".into(),
        }
    }
    #[test]
    fn duplicate_devices_keys_and_certificates_are_rejected() {
        let first = record("test-phone");
        let mut registry = ApproverRegistry {
            schema_version: 1,
            approvers: vec![first.clone()],
        };
        registry.validate().unwrap();
        registry.approvers.push(first.clone());
        assert!(registry.validate().is_err());
        registry.approvers[1].device_id = "different-phone".into();
        assert!(registry.validate().is_err());
    }
    #[test]
    fn invalid_key_classes_and_identifiers_are_rejected() {
        let mut entry = record("test-phone");
        entry.denial_public_x963_base64 = entry.approval_public_x963_base64.clone();
        assert!(entry.validate().is_err());
        entry = record("evil;id");
        assert!(entry.validate().is_err());
        entry = record("test-phone");
        entry.schema_version = 2;
        assert!(entry.validate().is_err());
    }
}
