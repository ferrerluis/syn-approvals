import test from 'node:test';
import assert from 'node:assert/strict';
import { parseState, canApprove } from '../src/state.ts';
const request = { id: 'pending-a', targetID: 'pi', targetName: 'Pi', executable: '"/usr/bin/true"', arguments: [], workingDirectory: '"/tmp"', invokingUser: 'test', runAsUser: 'root', expiresAt: 10000, authenticating: false };
const state = () => ({ schemaVersion: 1, deviceID: 'phone', developmentSigner: true, releaseID: '00000000000000', targets: [{ id: 'pi', name: 'Pi', connected: true }], requests: [request], setup: { host: '', port: 22, checking: false } });
test('unsupported state and malformed pending data cannot reach the review UI', () => {
  for (const mutate of [s => s.schemaVersion = 2, s => s.requests[0] = {...request, expiresAt: 'later'}, s => s.requests[0] = {...request, id: ''}, s => s.targets[0].connected = 'yes', s => s.requests.push({...request})]) {
    const value = state(); mutate(value); assert.throws(() => parseState(JSON.stringify(value)));
  }
});
test('masked arguments stay absent and requests retain typed fields', () => {
  const value = state(); value.requests[0] = {...request, arguments: [{index: 0}]};
  const parsed = parseState(JSON.stringify(value)); assert.equal(parsed.requests[0].arguments[0].value, undefined); assert.equal(parsed.requests[0].executable, request.executable);
});
test('approval becomes unavailable at expiry and during native authentication', () => {
  assert.equal(canApprove(request, 9999), true); assert.equal(canApprove(request, 10000), false);
  assert.equal(canApprove({...request, authenticating: true}, 9999), false);
});
