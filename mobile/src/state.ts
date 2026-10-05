export interface Argument { index: number; value?: string }
export interface Request {
  id: string; targetID: string; targetName: string; executable: string;
  arguments: Argument[]; workingDirectory: string; invokingUser: string; runAsUser: string;
  expiresAt: number; authenticating: boolean;
}
export interface State {
  schemaVersion: 1; deviceID: string; developmentSigner: boolean; releaseID: string;
  targets: { id: string; name: string; connected: boolean }[]; requests: Request[];
  setup: { host: string; port: number; checking: boolean; fingerprint?: string; bootstrapCommand?: string };
  error?: string; status?: string;
}
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const string = (value: unknown): value is string => typeof value === 'string';
export function parseState(json: string): State {
  const value: unknown = JSON.parse(json);
  if (!record(value) || value.schemaVersion !== 1 || !string(value.deviceID) || !string(value.releaseID)
      || typeof value.developmentSigner !== 'boolean' || !Array.isArray(value.targets) || !Array.isArray(value.requests)
      || !record(value.setup) || !string(value.setup.host) || !Number.isInteger(value.setup.port) || typeof value.setup.checking !== 'boolean') {
    throw new Error('Invalid native state. Syn cannot review requests.');
  }
  for (const target of value.targets) {
    if (!record(target) || !string(target.id) || !string(target.name) || typeof target.connected !== 'boolean') throw new Error('Invalid machine state.');
  }
  const ids = new Set<string>();
  for (const request of value.requests) {
    if (!record(request) || !string(request.id) || !request.id || ids.has(request.id)
      || !string(request.targetID) || !string(request.targetName) || !string(request.executable)
      || !string(request.workingDirectory) || !string(request.invokingUser) || !string(request.runAsUser)
      || typeof request.authenticating !== 'boolean' || typeof request.expiresAt !== 'number' || !Number.isFinite(request.expiresAt)
      || !Array.isArray(request.arguments) || request.arguments.some((arg: unknown) => !record(arg) || !Number.isInteger(arg.index) || !(arg.value === undefined || string(arg.value)))) throw new Error('Invalid pending request.');
    ids.add(request.id);
  }
  return value as unknown as State;
}
export function canApprove(request: Request, now = Date.now()): boolean { return !request.authenticating && request.expiresAt > now; }
