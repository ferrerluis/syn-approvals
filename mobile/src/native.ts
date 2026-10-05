import { requireOptionalNativeModule } from 'expo';
import { parseState, type State } from './state';
interface Bridge {
  getState(): Promise<string>; setActive(active: boolean): Promise<void>; retry(): Promise<void>;
  checkHost(host: string, port: number, user: string): Promise<void>; trustHost(): Promise<void>; pair(): Promise<void>;
  approve(id: string): Promise<void>; deny(id: string): Promise<void>; revealArgument(id: string, index: number): Promise<void>;
  addListener(event: 'onStateChanged', callback: (event: { state?: string; error?: string }) => void): { remove(): void };
}
export const native = requireOptionalNativeModule<Bridge>('SynNative');
export async function readState(): Promise<State> {
  if (!native) throw new Error('Use a locally built Syn iOS app. Native approvals are unavailable in Expo Go or on Android.');
  return parseState(await native.getState());
}
