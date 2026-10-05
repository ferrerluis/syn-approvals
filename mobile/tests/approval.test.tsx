import { jest, beforeEach, test, expect } from '@jest/globals';
import React from 'react';
import { fireEvent, render, waitFor } from '@testing-library/react-native';
import App from '../App';
import { native, readState } from '../src/native';
import type { State } from '../src/state';

jest.mock('../src/native', () => ({
  native: { addListener: jest.fn(() => ({ remove: jest.fn() })), setActive: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
    approve: jest.fn<() => Promise<void>>().mockResolvedValue(undefined), deny: jest.fn<() => Promise<void>>().mockResolvedValue(undefined), retry: jest.fn<() => Promise<void>>().mockResolvedValue(undefined) },
  readState: jest.fn(),
}));
const state = (): State => ({ schemaVersion: 1, deviceID: 'test-device', releaseID: '00000000000000', developmentSigner: true,
  targets: [{ id: 'test-target', name: 'Test machine', connected: true }], setup: { host: '', port: 22, checking: false },
  requests: [{ id: 'request-one', targetID: 'test-target', targetName: 'Test machine', executable: '/usr/bin/true',
    arguments: [{ index: 0, value: '/usr/bin/true' }, { index: 1 }], workingDirectory: '/home/test', invokingUser: 'test', runAsUser: 'root',
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
