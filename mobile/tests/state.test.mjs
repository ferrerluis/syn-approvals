import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseState, canApprove } from '../src/state.ts';
const request = { id: 'pending-a', targetID: 'pi', targetName: 'Pi', executable: '"/usr/bin/true"', arguments: [], workingDirectory: '"/tmp"', invokingUID: 1000, invokingUser: 'test', runAsUID: 0, runAsUser: 'root', runAsGroup: 'root', environmentNames: ['PATH'], environmentDigest: 'a7'.repeat(32), riskMarkers: ['noninteractive'], expiresAt: 10000, authenticating: false };
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

test('display data cannot hide malformed identities, digest, argument order or machine binding', () => {
  const mutations = [
    s => s.requests[0].invokingUID = -1,
    s => s.requests[0].runAsUID = 0x100000000,
    s => s.requests[0].environmentDigest = 'short',
    s => s.requests[0].environmentNames = [42],
    s => s.requests[0].riskMarkers = ['warning', null],
    s => s.requests[0].targetKeyFingerprint = 'invalid',
    s => s.requests[0].arguments = [{index: 0}, {index: 0}],
    s => s.requests[0].arguments = [{index: -1}],
    s => s.requests[0].targetID = 'other-machine',
    s => s.targets.push({...s.targets[0]}),
    s => s.setup.port = 0,
    s => s.setup.port = 65536,
    s => s.error = {unexpected: 'object'},
  ];
  for (const mutate of mutations) {
    const value = state(); value.requests = [{...request}]; mutate(value);
    assert.throws(() => parseState(JSON.stringify(value)));
  }
});
test('the native review golden includes identity and warnings without raw wire data', () => {
  const golden = JSON.parse(readFileSync(new URL('../../macos/Tests/SynTests/Fixtures/mobile-review.json', import.meta.url), 'utf8'));
  const value = state(); value.requests = [golden];
  assert.deepEqual(parseState(JSON.stringify(value)).requests[0], golden);
  assert.equal(golden.arguments[1].value, undefined);
  assert.equal(golden.signedBytes, undefined);
  assert.equal(golden.invokingUID, 1000);
  assert.equal(golden.environmentDigest, 'a7'.repeat(32));
});
