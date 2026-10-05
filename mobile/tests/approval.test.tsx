import { jest, beforeEach, test, expect } from '@jest/globals';
import React from 'react';
import { act, fireEvent, render, waitFor } from '@testing-library/react-native';
import App from '../App';
import { native, readState } from '../src/native';
import type { State } from '../src/state';

jest.mock('../src/native', () => ({
  native: { addListener: jest.fn(() => ({ remove: jest.fn() })), setActive: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
    pair: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
    approve: jest.fn<() => Promise<void>>().mockResolvedValue(undefined), deny: jest.fn<() => Promise<void>>().mockResolvedValue(undefined), retry: jest.fn<() => Promise<void>>().mockResolvedValue(undefined) },
  readState: jest.fn(),
}));
const state = (): State => ({ schemaVersion: 1, deviceID: 'test-device', releaseID: '00000000000000', developmentSigner: true,
  targets: [{ id: 'test-target', name: 'Test machine', connected: true }], setup: { host: '', port: 22, checking: false },
  requests: [{ id: 'request-one', targetID: 'test-target', targetName: 'Test machine', executable: '/usr/bin/true',
    arguments: [{ index: 0, value: '/usr/bin/true' }, { index: 1 }], workingDirectory: '/home/test', invokingUID: 1000, invokingUser: 'test', runAsUID: 0, runAsUser: 'root', runAsGroup: 'root', environmentNames: ['PATH'], environmentDigest: 'a7'.repeat(32), riskMarkers: ['noninteractive'],
    expiresAt: Date.now() + 90000, authenticating: false }] });
beforeEach(() => { jest.clearAllMocks(); jest.mocked(readState).mockResolvedValue(state()); });

test('Approve submits only the displayed request ID to native signing', async () => {
  const ui = render(<App />);
  await ui.findByText('/usr/bin/true');
  fireEvent.press(ui.getByTestId('approve-request-one'));
  await waitFor(() => expect(native!.approve).toHaveBeenCalledWith('request-one'));
  expect(jest.mocked(native!.approve).mock.calls[0]).toHaveLength(1);
  expect(ui.getByText('Approves this invocation only.')).toBeTruthy();
  expect(ui.getByText('Reveal argument 1')).toBeTruthy();
  ui.unmount();
});

test('Expired requests cannot invoke native approval', async () => {
  const expired = state(); expired.requests[0].expiresAt = Date.now() - 1;
  jest.mocked(readState).mockResolvedValue(expired);
  const ui = render(<App />);
  await ui.findByText('Expired');
  fireEvent.press(ui.getByTestId('approve-request-one'));
  expect(native!.approve).not.toHaveBeenCalled();
  ui.unmount();
});

test('Deny stays usable while native authentication is pending', async () => {
  const authenticating = state(); authenticating.requests[0].authenticating = true;
  jest.mocked(readState).mockResolvedValue(authenticating);
  const ui = render(<App />);
  await ui.findByText('Authenticating…');
  fireEvent.press(ui.getByTestId('deny-request-one'));
  expect(native!.deny).toHaveBeenCalledWith('request-one');
  expect(native!.approve).not.toHaveBeenCalled();
  ui.unmount();
});

test('Leaving the app closes native connections', async () => {
  const ui = render(<App />);
  await ui.findByText('Connected');
  await waitFor(() => expect(native!.setActive).toHaveBeenCalledWith(true));
  ui.unmount();
  expect(native!.setActive).toHaveBeenLastCalledWith(false);
});

test('A waiting setup operation cannot block approval of its live preflight request', async () => {
  const pairing = state(); pairing.setup.bootstrapCommand = 'Trusted administrator bootstrap';
  jest.mocked(readState).mockResolvedValue(pairing);
  let finishPairing!: () => void;
  jest.mocked(native!.pair).mockImplementation(() => new Promise<void>(resolve => { finishPairing = resolve; }));
  const ui = render(<App />);
  await ui.findByText('Connected');
  fireEvent.press(ui.getByTestId('add-machine'));
  fireEvent.press(ui.getByTestId('pair-machine'));
  expect(native!.pair).toHaveBeenCalled();
  fireEvent.press(ui.getByTestId('approve-request-one'));
  await waitFor(() => expect(native!.approve).toHaveBeenCalledWith('request-one'));
  await act(async () => finishPairing());
  ui.unmount();
});

test('Review shows native identities, group, environment digest and warnings', async () => {
  const ui = render(<App />);
  await ui.findByText('Source user: test (UID 1000)');
  expect(ui.getByText('Run as: root (UID 0), group root')).toBeTruthy();
  expect(ui.getByText('Environment names')).toBeTruthy();
  expect(ui.getByText('PATH')).toBeTruthy();
  expect(ui.getByText('a7'.repeat(32))).toBeTruthy();
  expect(ui.getByTestId('warnings-request-one').props.children.join('')).toContain('noninteractive');
  ui.unmount();
});

test('Malformed native events remove stale approval controls', async () => {
  const ui = render(<App />);
  await ui.findByText('Connected');
  const receive = jest.mocked(native!.addListener).mock.calls[0][1];
  await act(async () => receive({state: JSON.stringify({schemaVersion: 99})}));
  expect(ui.queryByTestId('approve-request-one')).toBeNull();
  expect(ui.getByText('Syn received invalid native state. Restart the app.')).toBeTruthy();
  expect(native!.approve).not.toHaveBeenCalled();
  ui.unmount();
});

test('A native storage error removes stale approval controls', async () => {
  const ui = render(<App />);
  await ui.findByText('Connected');
  const receive = jest.mocked(native!.addListener).mock.calls[0][1];
  await act(async () => receive({error: 'Syn could not open native storage.'}));
  expect(ui.queryByTestId('approve-request-one')).toBeNull();
  expect(ui.getByText('Syn could not open native storage.')).toBeTruthy();
  expect(native!.approve).not.toHaveBeenCalled();
  ui.unmount();
});

test('Changing the hostname hides stale fingerprint trust and enrollment controls', async () => {
  const checked = state(); checked.setup.host = 'trusted.example';
  checked.setup.fingerprint = 'SHA256:independently-verified';
  checked.setup.bootstrapCommand = 'Trusted administrator bootstrap';
  jest.mocked(readState).mockResolvedValue(checked);
  const ui = render(<App />);
  await ui.findByText('Connected');
  fireEvent.press(ui.getByTestId('add-machine'));
  fireEvent.changeText(ui.getByTestId('machine-host'), 'trusted.example');
  expect(ui.getByTestId('trust-host')).toBeTruthy();
  expect(ui.getByTestId('pair-machine')).toBeTruthy();
  fireEvent.changeText(ui.getByTestId('machine-host'), 'another.example');
  expect(ui.queryByTestId('trust-host')).toBeNull();
  expect(ui.queryByTestId('pair-machine')).toBeNull();
  expect(native!.pair).not.toHaveBeenCalled();
  ui.unmount();
});


test('Changing the Linux account hides setup controls bound to another account', async () => {
  const checked = state(); checked.setup.user = 'ferrerluis';
  checked.setup.fingerprint = 'SHA256:independently-verified';
  checked.setup.bootstrapCommand = 'Trusted administrator bootstrap';
  jest.mocked(readState).mockResolvedValue(checked);
  const ui = render(<App />);
  await ui.findByText('Connected');
  fireEvent.press(ui.getByTestId('add-machine'));
  expect(ui.getByTestId('pair-machine')).toBeTruthy();
  fireEvent.changeText(ui.getByTestId('machine-user'), 'another-user');
  expect(ui.queryByTestId('pair-machine')).toBeNull();
  expect(ui.queryByTestId('trust-host')).toBeNull();
  expect(native!.pair).not.toHaveBeenCalled();
  ui.unmount();
});
