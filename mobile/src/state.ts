export interface Argument { index: number; value?: string }
export interface Request {
  id: string; targetID: string; targetName: string; targetKeyFingerprint?: string; executable: string;
  arguments: Argument[]; workingDirectory: string; invokingUID: number; invokingUser: string;
  runAsUID: number; runAsUser: string; runAsGroup: string;
  environmentNames: string[]; environmentDigest: string; riskMarkers: string[];
  expiresAt: number; authenticating: boolean;
}
export interface State {
  schemaVersion: 1; deviceID: string; developmentSigner: boolean; releaseID: string;
  targets: { id: string; name: string; connected: boolean }[]; requests: Request[];
  setup: { host: string; port: number; user?: string; checking: boolean; fingerprint?: string; bootstrapCommand?: string };
  error?: string; status?: string;
}
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const string = (value: unknown): value is string => typeof value === 'string';
const optionalString = (value: unknown) => value === undefined || string(value);
const uint32 = (value: unknown) => typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
const digest = (value: unknown) => string(value) && /^[a-f0-9]{64}$/.test(value);
const strings = (value: unknown, limit: number): value is string[] => Array.isArray(value) && value.length <= limit && value.every(string);
export function parseState(json: string): State {
  const value: unknown = JSON.parse(json);
  if (!record(value) || value.schemaVersion !== 1 || !string(value.deviceID) || !value.deviceID || !string(value.releaseID)
      || typeof value.developmentSigner !== 'boolean' || !Array.isArray(value.targets) || !Array.isArray(value.requests)
      || !record(value.setup) || !string(value.setup.host) || typeof value.setup.port !== 'number' || !Number.isInteger(value.setup.port)
      || value.setup.port < 1 || value.setup.port > 65535 || typeof value.setup.checking !== 'boolean'
      || !optionalString(value.setup.user) || !optionalString(value.setup.fingerprint) || !optionalString(value.setup.bootstrapCommand)
      || !optionalString(value.error) || !optionalString(value.status)) {
    throw new Error('Invalid native state. Syn cannot review requests.');
  }
  const targetIDs = new Set<string>();
  for (const target of value.targets) {
    if (!record(target) || !string(target.id) || !target.id || targetIDs.has(target.id) || !string(target.name)
      || typeof target.connected !== 'boolean') throw new Error('Invalid machine state.');
    targetIDs.add(target.id);
  }
  const ids = new Set<string>();
  for (const request of value.requests) {
    if (!record(request) || !string(request.id) || !request.id || ids.has(request.id)
      || !string(request.targetID) || !targetIDs.has(request.targetID) || !string(request.targetName) || !string(request.executable)
      || !(request.targetKeyFingerprint === undefined || digest(request.targetKeyFingerprint))
      || !string(request.workingDirectory) || !uint32(request.invokingUID) || !string(request.invokingUser)
      || !uint32(request.runAsUID) || !string(request.runAsUser) || !string(request.runAsGroup)
      || !strings(request.environmentNames, 1024) || !digest(request.environmentDigest) || !strings(request.riskMarkers, 128)
      || typeof request.authenticating !== 'boolean' || typeof request.expiresAt !== 'number' || !Number.isFinite(request.expiresAt)
      || !Array.isArray(request.arguments) || request.arguments.length > 256
      || request.arguments.some((arg: unknown, index: number) => !record(arg) || arg.index !== index || !optionalString(arg.value))) {
      throw new Error('Invalid pending request.');
    }
    ids.add(request.id);
  }
  return value as unknown as State;
}
export function canApprove(request: Request, now = Date.now()): boolean { return !request.authenticating && request.expiresAt > now; }
