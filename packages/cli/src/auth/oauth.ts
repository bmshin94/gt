import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  chmod,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import open from 'open';
import type { UserTokenProvider } from 'generaltranslation/api';
import { defaultBaseUrl } from 'generaltranslation/internal';
import { GT_DASHBOARD_URL } from '../utils/constants.js';
import { logger } from '../console/logger.js';
import { startLoopbackServer, type AuthorizationCallback } from './loopback.js';

/**
 * Well-known public client seeded by gt-cloud (`GT_CLI_OAUTH_CLIENT_ID`).
 * Public clients cannot prove their identity, so the id is not a secret; the
 * provider still shows the consent screen on every login.
 */
export const OAUTH_CLIENT_ID = 'gt-cli';

/**
 * Scopes requested by `gt login`. The provider rejects unknown scopes, so each
 * entry must exist in gt-cloud's oauthProviderConfig. Permission scopes map to
 * the CLI commands that call operations requiring them:
 * - openid, profile: identity/name/email for `gt whoami`
 * - offline_access: refresh tokens so logins outlive the 1h access token
 * - project:files:read: stage/download/status polling, project + branch + file info, orphaned files
 * - project:files:write: upload sources/translations, branches, tags, publish, moves, user-edit diffs, fonts
 * - project:translations:enqueue: translate/enqueue
 * - project:translations:generate: runtime `POST /v2/translate` used by `gt api` and dev workflows
 * - project:context:write: `gt setup`'s project context generation
 * - org:projects:create: `gt project create`
 */
export const OAUTH_SCOPE =
  'openid profile offline_access project:files:read project:files:write project:translations:enqueue project:translations:generate project:context:write org:projects:create';

const DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';
// RFC 8628 §3.5: add 5 seconds to the polling interval on `slow_down`.
const SLOW_DOWN_INCREMENT_SECONDS = 5;
// Distinct from defaultTimeout on purpose: refresh slightly before expiry so
// an in-flight request never carries a token that expires mid-request.
const TOKEN_REFRESH_BUFFER_MS = 30_000;

export type OAuthTokens = {
  accessToken: string;
  expiresAt: number;
  refreshToken: string;
  scope: string;
  tokenType: string;
};

type StoredServerCredentials = {
  tokens?: OAuthTokens;
};

type StoredCredentials = {
  version: 2;
  /** Keyed by authorization server base URL so dev and prod logins coexist. */
  servers: Record<string, StoredServerCredentials>;
};

export type DeviceCode = {
  deviceCode: string;
  expiresIn: number;
  interval: number;
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string;
};

export type UserInfo = {
  email?: string;
  name?: string;
  sub: string;
};

type OAuthRequestOptions = {
  authBaseUrl?: string;
  fetch?: typeof fetch;
};

type OpenBrowser = (url: string) => Promise<unknown>;

export type LoginOptions = OAuthRequestOptions & {
  apiResource?: string;
  /**
   * Use the device grant without opening a browser: the verification URL and
   * user code are reported through onDeviceCode for the user to enter elsewhere.
   */
  noBrowser?: boolean;
  now?: () => number;
  onAuthorizationUrl?: (url: string) => void;
  /** Called when login falls back to the device grant, before polling starts. */
  onDeviceCode?: (deviceCode: DeviceCode) => void;
  openBrowser?: OpenBrowser;
  sleep?: (milliseconds: number) => Promise<void>;
  timeoutMs?: number;
};

export type PkcePair = { codeVerifier: string; codeChallenge: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function stringField(value: Record<string, unknown>, key: string): string {
  const field = value[key];
  if (typeof field !== 'string' || !field) {
    throw new Error(`OAuth response is missing ${key}`);
  }
  return field;
}

function numberField(value: Record<string, unknown>, key: string): number {
  const field = value[key];
  if (typeof field !== 'number' || !Number.isFinite(field)) {
    throw new Error(`OAuth response is missing ${key}`);
  }
  return field;
}

function optionalStringField(
  value: Record<string, unknown>,
  key: string
): string | undefined {
  const field = value[key];
  return typeof field === 'string' && field ? field : undefined;
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const value: unknown = await response.json();
  if (!isRecord(value)) throw new Error('OAuth server returned invalid JSON');
  return value;
}

async function readOAuthError(
  response: Response
): Promise<{ error?: string; description?: string }> {
  try {
    const value: unknown = await response.json();
    if (isRecord(value)) {
      return {
        error: optionalStringField(value, 'error'),
        description: optionalStringField(value, 'error_description'),
      };
    }
  } catch {
    // OAuth servers may return an empty or non-JSON error response.
  }
  return {};
}

class OAuthError extends Error {
  constructor(
    message: string,
    readonly code?: string
  ) {
    super(message);
  }
}

async function createOAuthError(
  response: Response,
  fallback: string
): Promise<OAuthError> {
  const { error, description } = await readOAuthError(response);
  return new OAuthError(
    describeOAuthError(error, description, fallback),
    error
  );
}

function describeOAuthError(
  error: string | undefined,
  description: string | undefined,
  fallback: string
): string {
  switch (error) {
    case 'access_denied':
      return 'Sign in was denied in the browser';
    case 'expired_token':
      return 'The sign-in code expired before it was approved. Run `gt login` again';
    case 'invalid_scope':
      return `The authorization server rejected the requested scopes${description ? `: ${description}` : ''}`;
    case 'invalid_grant':
      return 'The sign-in code expired or was already used. Run `gt login` again';
    case 'invalid_client':
    case 'unauthorized_client':
      return 'This authorization server does not recognize the gt CLI. Check GT_AUTH_URL or update the server';
    default:
      return description ?? error ?? fallback;
  }
}

function parseTokens(
  value: Record<string, unknown>,
  previous?: OAuthTokens,
  now = Date.now()
): OAuthTokens {
  return {
    accessToken: stringField(value, 'access_token'),
    expiresAt: now + numberField(value, 'expires_in') * 1000,
    refreshToken:
      optionalStringField(value, 'refresh_token') ??
      previous?.refreshToken ??
      '',
    scope:
      optionalStringField(value, 'scope') ?? previous?.scope ?? OAUTH_SCOPE,
    tokenType:
      optionalStringField(value, 'token_type') ??
      previous?.tokenType ??
      'Bearer',
  };
}

export function getAuthBaseUrl(): string {
  return (process.env.GT_AUTH_URL ?? `${GT_DASHBOARD_URL}/api/auth`).replace(
    /\/$/,
    ''
  );
}

/** The API resource identifier is the API origin serialized as a URL href (trailing slash). */
export function getApiResource(): string {
  return new URL(process.env.GT_API_URL ?? defaultBaseUrl).href;
}

export function getCredentialsPath(): string {
  const configHome =
    process.env.XDG_CONFIG_HOME || path.join(homedir(), '.config');
  return path.join(configHome, 'gt', 'credentials.json');
}

// ---------------------------------------------------------------------------
// Credentials file
// ---------------------------------------------------------------------------

/** An unreadable file is set aside (not deleted) and treated as logged out. */
async function readCredentialsFile(): Promise<StoredCredentials> {
  const credentialsPath = getCredentialsPath();
  let contents: string;
  try {
    contents = await readFile(credentialsPath, 'utf8');
  } catch (error) {
    if (isRecord(error) && error.code === 'ENOENT') {
      return { version: 2, servers: {} };
    }
    throw error;
  }

  try {
    const parsed: unknown = JSON.parse(contents);
    if (
      !isRecord(parsed) ||
      parsed.version !== 2 ||
      !isRecord(parsed.servers)
    ) {
      throw new Error('expected version 2 with a servers object');
    }
    return parsed as StoredCredentials;
  } catch {
    const backupPath = `${credentialsPath}.corrupt-${Date.now()}`;
    await rename(credentialsPath, backupPath);
    logger.warn(
      `Stored OAuth credentials were invalid and have been reset. The unreadable file was moved to ${backupPath}`
    );
    return { version: 2, servers: {} };
  }
}

async function writeCredentialsFile(
  credentials: StoredCredentials
): Promise<void> {
  const credentialsPath = getCredentialsPath();
  const directory = path.dirname(credentialsPath);
  const temporaryPath = path.join(
    directory,
    `.credentials-${randomUUID()}.tmp`
  );

  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(temporaryPath, `${JSON.stringify(credentials, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  try {
    await rename(temporaryPath, credentialsPath);
    await chmod(credentialsPath, 0o600);
  } catch (error) {
    await rm(temporaryPath, { force: true });
    throw error;
  }
}

async function updateServerCredentials(
  authBaseUrl: string,
  update: (current: StoredServerCredentials) => StoredServerCredentials | null
): Promise<void> {
  const credentials = await readCredentialsFile();
  const next = update(credentials.servers[authBaseUrl] ?? {});
  if (next === null || !next.tokens) {
    delete credentials.servers[authBaseUrl];
  } else {
    credentials.servers[authBaseUrl] = next;
  }
  if (Object.keys(credentials.servers).length === 0) {
    await rm(getCredentialsPath(), { force: true });
    return;
  }
  await writeCredentialsFile(credentials);
}

export async function readOAuthTokens(
  authBaseUrl = getAuthBaseUrl()
): Promise<OAuthTokens | undefined> {
  return (await readCredentialsFile()).servers[authBaseUrl]?.tokens;
}

export async function writeOAuthTokens(
  tokens: OAuthTokens,
  authBaseUrl = getAuthBaseUrl()
): Promise<void> {
  await updateServerCredentials(authBaseUrl, (current) => ({
    ...current,
    tokens,
  }));
}

export async function deleteOAuthTokens(
  authBaseUrl = getAuthBaseUrl()
): Promise<void> {
  await updateServerCredentials(authBaseUrl, () => null);
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

export function createPkcePair(
  codeVerifier = randomBytes(32).toString('base64url')
): PkcePair {
  return {
    codeVerifier,
    codeChallenge: createHash('sha256')
      .update(codeVerifier)
      .digest('base64url'),
  };
}

// ---------------------------------------------------------------------------
// Authorization code + PKCE
// ---------------------------------------------------------------------------

export function buildAuthorizationUrl({
  authBaseUrl,
  clientId,
  redirectUri,
  codeChallenge,
  state,
  apiResource,
}: {
  authBaseUrl: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string;
  apiResource: string;
}): string {
  const url = new URL(`${authBaseUrl}/oauth2/authorize`);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: OAUTH_SCOPE,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    resource: apiResource,
  }).toString();
  return url.toString();
}

export async function exchangeAuthorizationCode({
  authBaseUrl = getAuthBaseUrl(),
  fetch: fetchImplementation = globalThis.fetch,
  clientId,
  code,
  codeVerifier,
  redirectUri,
  apiResource,
}: OAuthRequestOptions & {
  clientId: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
  apiResource: string;
}): Promise<OAuthTokens> {
  const response = await fetchImplementation(`${authBaseUrl}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
      resource: apiResource,
    }),
  });
  if (!response.ok) {
    throw await createOAuthError(response, 'Could not complete sign in');
  }
  return parseTokens(await readJson(response));
}

function assertCallback(
  callback: AuthorizationCallback,
  expectedState: string
): string {
  if (callback.error) {
    throw new OAuthError(
      describeOAuthError(
        callback.error,
        callback.errorDescription,
        'Sign in failed'
      ),
      callback.error
    );
  }
  if (callback.state !== expectedState) {
    throw new Error(
      'Sign in response did not match this login attempt (state mismatch). Run `gt login` again'
    );
  }
  if (!callback.code) {
    throw new Error('Sign in response did not include an authorization code');
  }
  return callback.code;
}

// ---------------------------------------------------------------------------
// Device authorization grant (RFC 8628)
// ---------------------------------------------------------------------------

export async function requestDeviceCode({
  authBaseUrl = getAuthBaseUrl(),
  apiResource = getApiResource(),
  fetch: fetchImplementation = globalThis.fetch,
}: OAuthRequestOptions & { apiResource?: string } = {}): Promise<DeviceCode> {
  const response = await fetchImplementation(`${authBaseUrl}/device/code`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: OAUTH_CLIENT_ID,
      scope: OAUTH_SCOPE,
      resource: apiResource,
    }),
  });
  if (!response.ok) {
    throw await createOAuthError(response, 'Could not start sign in');
  }
  const value = await readJson(response);
  return {
    deviceCode: stringField(value, 'device_code'),
    expiresIn: numberField(value, 'expires_in'),
    interval: numberField(value, 'interval'),
    userCode: stringField(value, 'user_code'),
    verificationUri: stringField(value, 'verification_uri'),
    verificationUriComplete: optionalStringField(
      value,
      'verification_uri_complete'
    ),
  };
}

export async function pollDeviceToken({
  authBaseUrl = getAuthBaseUrl(),
  apiResource = getApiResource(),
  deviceCode,
  fetch: fetchImplementation = globalThis.fetch,
  now = Date.now,
  sleep = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
}: OAuthRequestOptions & {
  apiResource?: string;
  deviceCode: DeviceCode;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}): Promise<OAuthTokens> {
  const deadline = now() + deviceCode.expiresIn * 1000;
  let intervalSeconds = deviceCode.interval;

  while (now() < deadline) {
    await sleep(intervalSeconds * 1000);
    const response = await fetchImplementation(`${authBaseUrl}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: DEVICE_CODE_GRANT_TYPE,
        client_id: OAUTH_CLIENT_ID,
        device_code: deviceCode.deviceCode,
        resource: apiResource,
      }),
    });
    const value = await readJson(response);
    if (response.ok) return parseTokens(value, undefined, now());

    const error = optionalStringField(value, 'error');
    if (error === 'authorization_pending') continue;
    if (error === 'slow_down') {
      intervalSeconds += SLOW_DOWN_INCREMENT_SECONDS;
      continue;
    }
    throw new Error(
      describeOAuthError(
        error,
        optionalStringField(value, 'error_description'),
        'Sign in failed'
      )
    );
  }
  throw new Error(describeOAuthError('expired_token', undefined, ''));
}

async function loginWithDeviceCode(
  options: LoginOptions,
  authBaseUrl: string,
  apiResource: string
): Promise<OAuthTokens> {
  const deviceCode = await requestDeviceCode({
    authBaseUrl,
    apiResource,
    fetch: options.fetch,
  });
  options.onDeviceCode?.(deviceCode);
  if (!options.noBrowser) {
    await (options.openBrowser ?? open)(
      deviceCode.verificationUriComplete ?? deviceCode.verificationUri
    ).catch(() => undefined);
  }
  const tokens = await pollDeviceToken({
    authBaseUrl,
    apiResource,
    deviceCode,
    fetch: options.fetch,
    now: options.now,
    sleep: options.sleep,
  });
  await writeOAuthTokens(tokens, authBaseUrl);
  return tokens;
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

/**
 * Authorization code + PKCE over a loopback redirect when a browser can open
 * on this machine; otherwise (`--no-browser`, or the loopback listener cannot
 * bind) the device grant, where the user enters a short code on any device.
 */
export async function login(options: LoginOptions = {}): Promise<OAuthTokens> {
  const authBaseUrl = options.authBaseUrl ?? getAuthBaseUrl();
  const apiResource = options.apiResource ?? getApiResource();
  if (options.noBrowser) {
    return loginWithDeviceCode(options, authBaseUrl, apiResource);
  }
  let loopback: Awaited<ReturnType<typeof startLoopbackServer>>;
  try {
    loopback = await startLoopbackServer();
  } catch {
    return loginWithDeviceCode(options, authBaseUrl, apiResource);
  }

  const { codeVerifier, codeChallenge } = createPkcePair();
  const state = randomBytes(16).toString('base64url');

  let code: string;
  try {
    const callback = loopback.waitForCallback(options.timeoutMs);
    callback.catch(() => undefined);
    const authorizationUrl = buildAuthorizationUrl({
      authBaseUrl,
      clientId: OAUTH_CLIENT_ID,
      redirectUri: loopback.redirectUri,
      codeChallenge,
      state,
      apiResource,
    });
    options.onAuthorizationUrl?.(authorizationUrl);
    await (options.openBrowser ?? open)(authorizationUrl).catch(
      () => undefined
    );
    code = assertCallback(await callback, state);
  } finally {
    loopback.close();
  }

  const tokens = await exchangeAuthorizationCode({
    authBaseUrl,
    fetch: options.fetch,
    clientId: OAUTH_CLIENT_ID,
    code,
    codeVerifier,
    redirectUri: loopback.redirectUri,
    apiResource,
  });
  await writeOAuthTokens(tokens, authBaseUrl);
  return tokens;
}

// ---------------------------------------------------------------------------
// Refresh / logout / userinfo
// ---------------------------------------------------------------------------

const pendingRefreshes = new Map<string, Promise<OAuthTokens>>();

export async function refreshOAuthTokens({
  authBaseUrl = getAuthBaseUrl(),
  fetch: fetchImplementation = globalThis.fetch,
}: OAuthRequestOptions = {}): Promise<OAuthTokens> {
  const pending = pendingRefreshes.get(authBaseUrl);
  if (pending) return pending;
  const refresh = exchangeRefreshToken(authBaseUrl, fetchImplementation);
  pendingRefreshes.set(authBaseUrl, refresh);
  try {
    return await refresh;
  } finally {
    pendingRefreshes.delete(authBaseUrl);
  }
}

async function exchangeRefreshToken(
  authBaseUrl: string,
  fetchImplementation: typeof fetch
): Promise<OAuthTokens> {
  const current = await readOAuthTokens(authBaseUrl);
  if (!current?.refreshToken) throw new Error('Run `gt login` to sign in');

  const response = await fetchImplementation(`${authBaseUrl}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: OAUTH_CLIENT_ID,
      grant_type: 'refresh_token',
      refresh_token: current.refreshToken,
    }),
  });
  if (!response.ok) {
    const { error, description } = await readOAuthError(response);
    if (
      error !== 'invalid_client' &&
      (response.status === 401 ||
        error === 'invalid_grant' ||
        error === 'invalid_token')
    ) {
      throw new Error('Your login expired. Run `gt login` to sign in again');
    }
    throw new OAuthError(
      describeOAuthError(
        error,
        description,
        `Could not refresh your login (HTTP ${response.status})`
      ),
      error
    );
  }
  const tokens = parseTokens(await readJson(response), current);
  await writeOAuthTokens(tokens, authBaseUrl);
  return tokens;
}

export async function getValidAccessToken(
  options: OAuthRequestOptions = {}
): Promise<string | undefined> {
  const authBaseUrl = options.authBaseUrl ?? getAuthBaseUrl();
  const tokens = await readOAuthTokens(authBaseUrl);
  if (!tokens) return undefined;
  if (tokens.expiresAt > Date.now() + TOKEN_REFRESH_BUFFER_MS) {
    return tokens.accessToken;
  }
  return (await refreshOAuthTokens({ ...options, authBaseUrl })).accessToken;
}

/** API client credentials backed by the signed-in user; reads and refreshes lazily. */
export function createUserTokenProvider(): UserTokenProvider {
  return {
    getAccessToken: async () => {
      const accessToken = await getValidAccessToken();
      if (!accessToken) throw new Error('Run `gt login` to sign in');
      return accessToken;
    },
    refreshAccessToken: async () => (await refreshOAuthTokens()).accessToken,
  };
}

export async function logout({
  authBaseUrl = getAuthBaseUrl(),
  fetch: fetchImplementation = globalThis.fetch,
}: OAuthRequestOptions = {}): Promise<void> {
  const tokens = await readOAuthTokens(authBaseUrl);
  try {
    if (tokens?.refreshToken) {
      const response = await fetchImplementation(
        `${authBaseUrl}/oauth2/revoke`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: OAUTH_CLIENT_ID,
            token: tokens.refreshToken,
            token_type_hint: 'refresh_token',
          }),
        }
      );
      if (!response.ok) {
        logger.warn(
          `Signed out locally, but the authorization server did not revoke the session (HTTP ${response.status})`
        );
      }
    }
  } finally {
    await deleteOAuthTokens(authBaseUrl);
  }
}

export async function whoAmI({
  authBaseUrl = getAuthBaseUrl(),
  fetch: fetchImplementation = globalThis.fetch,
}: OAuthRequestOptions = {}): Promise<UserInfo> {
  const accessToken = await getValidAccessToken({
    authBaseUrl,
    fetch: fetchImplementation,
  });
  if (!accessToken) throw new Error('Run `gt login` to sign in');
  const response = await fetchImplementation(`${authBaseUrl}/oauth2/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw await createOAuthError(
      response,
      `Could not load your account (HTTP ${response.status})`
    );
  }
  const value = await readJson(response);
  return {
    sub: stringField(value, 'sub'),
    email: optionalStringField(value, 'email'),
    name: optionalStringField(value, 'name'),
  };
}
