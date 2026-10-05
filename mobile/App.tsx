import React, { useEffect, useState } from 'react';
import { Alert, AppState, Keyboard, Pressable, SafeAreaView, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { native, readState } from './src/native';
import { canApprove, parseState, type State } from './src/state';

function Button({ label, onPress, disabled = false, danger = false, testID }: { label: string; onPress(): void; disabled?: boolean; danger?: boolean; testID: string }) {
  return <Pressable accessibilityRole="button" accessibilityLabel={label} accessibilityState={{ disabled }} testID={testID} disabled={disabled} onPress={onPress} style={[styles.button, danger && styles.danger, disabled && styles.disabled]}><Text style={styles.buttonText}>{label}</Text></Pressable>;
}
export default function App() {
  const [state, setState] = useState<State>();
  const [error, setError] = useState<string>();
  const [setup, setSetup] = useState(false);
  const [host, setHost] = useState('');
  const [port, setPort] = useState('22');
  const [user, setUser] = useState('ferrerluis');
  const [busy, setBusy] = useState(false);
  const [approving, setApproving] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    let mounted = true;
    const receive = (json: string) => { try { if (mounted) setState(parseState(json)); } catch { if (mounted) { setState(undefined); setError('Syn received invalid native state. Restart the app.'); } } };
    const listener = native?.addListener('onStateChanged', event => { if (event.state) receive(event.state); else if (event.error) { setState(undefined); setError(event.error); } });
    const active = AppState.addEventListener('change', value => { native?.setActive(value === 'active').catch(() => setError('Syn could not change connection state.')); });
    readState().then(value => { if (mounted) setState(value); return native?.setActive(true); }).catch(e => setError(e.message));
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => { mounted = false; listener?.remove(); active.remove(); clearInterval(timer); native?.setActive(false).catch(() => {}); };
  }, []);
  const action = async (operation: () => Promise<unknown>, kind: 'setup' | 'approval' = 'setup') => {
    if (kind === 'approval' ? approving : busy) return;
    Keyboard.dismiss();
    const setWorking = kind === 'approval' ? setApproving : setBusy;
    setWorking(true); setError(undefined);
    try { await operation(); try { setState(await readState()); } catch (error) { setState(undefined); throw error; } } catch { setError('Syn could not complete that action. Check the connection and retry.'); }
    finally { setWorking(false); }
  };
  const setupMatches = state?.setup.host.trim() === host.trim() && state.setup.port === Number(port) && (state.setup.user ?? 'ferrerluis') === user;
  return <SafeAreaView style={styles.safe}><StatusBar style="dark" /><ScrollView contentContainerStyle={styles.page} keyboardShouldPersistTaps="handled">
    <View style={styles.heading}><View><Text style={styles.title}>Syn</Text><Text style={styles.subtitle}>Review remote approvals</Text></View><Button testID="add-machine" label={setup ? 'Done' : 'Add a machine'} onPress={() => setSetup(!setup)} /></View>
    {state?.developmentSigner && <View style={styles.notice}><Text style={styles.bold}>Simulator development signer</Text><Text style={styles.secondary}>Hardware authentication is not tested here.</Text></View>}
    {(error || state?.error) && <Text accessibilityRole="alert" testID="error" style={styles.error}>{error || state?.error}</Text>}
    {state?.status && <Text testID="status" style={styles.secondary}>{state.status}</Text>}
    {setup && native && <View style={styles.card}><Text style={styles.section}>Add a machine</Text><Text style={styles.secondary}>Connect directly using its hostname and SSH port.</Text>
      <TextInput accessibilityLabel="Machine hostname" testID="machine-host" value={host} onChangeText={setHost} placeholder="Machine hostname" autoCapitalize="none" autoCorrect={false} style={styles.input} />
      <TextInput accessibilityLabel="SSH port" testID="machine-port" value={port} onChangeText={setPort} keyboardType="number-pad" style={styles.input} />
      <TextInput accessibilityLabel="Linux account" testID="machine-user" value={user} onChangeText={setUser} placeholder="Linux account" autoCapitalize="none" autoCorrect={false} style={styles.input} />
      <Button testID="check-host" label="Check machine" disabled={busy || !host || !user || !/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535} onPress={() => void action(() => native!.checkHost(host, Number(port), user))} />
      {setupMatches && state?.setup.fingerprint && <><Text style={styles.bold}>Verify SSH fingerprint</Text><Text selectable style={styles.mono} testID="host-fingerprint">{state.setup.fingerprint}</Text><Text style={styles.secondary}>Compare this with a trusted administrator session before continuing.</Text><Button testID="trust-host" label="Trust verified machine" disabled={busy} onPress={() => void action(() => native!.trustHost())} /></>}
      {setupMatches && state?.setup.bootstrapCommand && <><Text style={styles.secondary}>Have a trusted administrator verify and stage this release’s helper at /var/tmp/syn-bootstrap.mobile/synctl, then run this command.</Text><Text selectable style={styles.mono}>{state.setup.bootstrapCommand}</Text><Button testID="pair-machine" label="Set up or update Syn" disabled={busy} onPress={() => void action(() => native!.pair())} /></>}
    </View>}
    <Text style={styles.section}>Machines</Text>
    {!state?.targets.length && <Text style={styles.secondary}>Add a machine to receive approval requests.</Text>}
    {state?.targets.map(target => <View key={target.id} style={styles.card}><View style={styles.row}><Text style={styles.bold}>{target.name}</Text><Text testID={`connection-${target.id}`} style={target.connected ? styles.connected : styles.secondary}>{target.connected ? 'Connected' : 'Disconnected'}</Text></View></View>)}
    {native && <Button testID="retry" label="Retry connection" disabled={busy} onPress={() => void action(() => native!.retry())} />}
    <Text style={styles.section}>Requests</Text>
    {!state?.requests.length && <Text testID="empty-requests" style={styles.secondary}>{state ? 'No pending requests' : 'Requests unavailable'}</Text>}
    {state?.requests.map(request => <View key={request.id} testID={`request-${request.id}`} style={styles.card}>
      <Text style={styles.bold}>{request.targetName}</Text>
      <Text style={styles.secondary}>Machine ID</Text><Text selectable style={styles.mono}>{request.targetID}</Text>
      <Text style={styles.secondary}>Machine fingerprint</Text><Text selectable style={styles.mono}>{request.targetKeyFingerprint ?? 'Unavailable'}</Text>
      <Text style={styles.secondary}>Source user: {request.invokingUser} (UID {request.invokingUID})</Text>
      <Text style={styles.secondary}>Run as: {request.runAsUser} (UID {request.runAsUID}), group {request.runAsGroup}</Text>
      <Text selectable style={styles.mono}>{request.executable}</Text>
      {request.arguments.map(arg => arg.value !== undefined ? <Text key={arg.index} style={styles.mono}>Argument {arg.index}: {arg.value}</Text> : <Button key={arg.index} testID={`reveal-${request.id}-${arg.index}`} label={`Reveal argument ${arg.index}`} onPress={() => Alert.alert('Reveal argument?', 'This argument may contain a secret.', [{ text: 'Cancel' }, { text: 'Reveal', onPress: () => void action(() => native!.revealArgument(request.id, arg.index)) }])} />)}
      <Text style={styles.secondary}>Working directory</Text><Text selectable style={styles.mono}>{request.workingDirectory}</Text>
      <Text style={styles.secondary}>Environment names</Text><Text selectable style={styles.mono}>{request.environmentNames.length ? request.environmentNames.join(', ') : 'None'}</Text>
      <Text style={styles.secondary}>Environment digest</Text><Text selectable style={styles.mono}>{request.environmentDigest}</Text>
      {request.riskMarkers.length > 0 && <Text accessibilityRole="alert" testID={`warnings-${request.id}`} style={styles.warning}>Warnings: {request.riskMarkers.join(', ')}</Text>}
      <Text style={styles.secondary}>{request.expiresAt <= now ? 'Expired' : `Expires in ${Math.ceil((request.expiresAt - now) / 1000)} seconds`}</Text>
      <Text style={styles.secondary}>Approves this invocation only.</Text>
      <View style={styles.row}><View style={styles.flex}><Button testID={`approve-${request.id}`} label={request.authenticating ? 'Authenticating…' : 'Approve'} disabled={approving || !canApprove(request, now)} onPress={() => void action(() => native!.approve(request.id), 'approval')} /></View><View style={styles.flex}><Button testID={`deny-${request.id}`} label="Deny" danger disabled={request.expiresAt <= now} onPress={() => void native!.deny(request.id).catch(() => setError('Denial delivery could not be confirmed.'))} /></View></View>
    </View>)}
    <Text style={styles.footer}>For Codex tasks, Codex can alert you when Syn needs attention. Open Syn to review the request directly.</Text>
    {state && <Text style={styles.footer}>Release {state.releaseID}</Text>}
  </ScrollView></SafeAreaView>;
}
const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#f5f7f7' }, page: { padding: 20, gap: 14, paddingBottom: 40 },
  heading: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 12 }, title: { fontSize: 34, fontWeight: '700', color: '#173c36' }, subtitle: { color: '#526760', fontSize: 14 },
  section: { fontSize: 21, fontWeight: '600', marginTop: 6, color: '#173c36' }, bold: { fontSize: 17, fontWeight: '600', color: '#173c36' }, secondary: { fontSize: 14, color: '#526760', lineHeight: 21 },
  card: { backgroundColor: '#fff', padding: 18, borderRadius: 16, gap: 12, borderWidth: 1, borderColor: '#dce6e2' }, notice: { backgroundColor: '#fff4d7', padding: 14, borderRadius: 12, gap: 4 },
  mono: { fontFamily: 'Menlo', fontSize: 13, color: '#243c35', lineHeight: 21 }, row: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: 12 }, flex: { flex: 1 },
  button: { paddingVertical: 12, paddingHorizontal: 14, backgroundColor: '#17694f', borderRadius: 10, alignItems: 'center' }, buttonText: { color: '#fff', fontSize: 14, fontWeight: '600' }, danger: { backgroundColor: '#a7343b' }, disabled: { opacity: 0.45 },
  warning: { color: '#87500d', lineHeight: 22 }, connected: { color: '#17694f', fontWeight: '600' }, error: { color: '#a7343b', lineHeight: 22 }, input: { borderWidth: 1, borderColor: '#d2ded8', borderRadius: 10, padding: 12, fontSize: 16 }, footer: { fontSize: 12, color: '#526760', lineHeight: 18 },
});
