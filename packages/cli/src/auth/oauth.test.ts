import {
  chmod,
  mkdtemp,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../console/logger.js';
import {
  buildAuthorizationUrl,
  createPkcePair,
  createUserTokenProvider,
  deleteOAuthTokens,
  exchangeAuthorizationCode,
  getApiResource,
  getCredentialsPath,
  getValidAccessToken,
  login,
  logout,
  OAUTH_CLIENT_ID,
  OAUTH_SCOPE,
  pollDeviceToken,
  readOAuthTokens,
  refreshOAuthTokens,
  requestDeviceCode,
  whoAmI,
  type DeviceCode,
  writeOAuthTokens,
  type OAuthTokens,
} from './oauth.js';

const authBaseUrl = 'https://auth.example/api/auth';
const apiResource = 'https://api.example/';

const tokens: OAuthTokens = {
  accessToken: 'access-1',
  expiresAt: Date.now() + 3_600_000,
  refreshToken: 'refresh-1',
  scope: 'openid project:files:read',
  tokenType: 'Bearer',
};

const deviceCode: DeviceCode = {
  deviceCode: 'device-1',
  expiresIn: 900,
  interval: 5,
  userCode: 'ABCD-EFGH',
  verificationUri: 'https://dash.example/device',
  verificationUriComplete: 'https://dash.example/device?user_code=ABCD-EFGH',
};

function deviceCodeResponse(): Record<string, unknown> {
  return {
    device_code: deviceCode.deviceCode,
    user_code: deviceCode.userCode,
    verification_uri: deviceCode.verificationUri,
    verification_uri_complete: deviceCode.verificationUriComplete,
    expires_in: deviceCode.expiresIn,
    interval: deviceCode.interval,
  };
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function tokenResponse(
  accessToken: string,
  refreshToken: string
): Record<string, unknown> {
  return {
    access_token: accessToken,
    expires_in: 3600,
    refresh_token: refreshToken,
    scope: 'openid project:files:read',
    token_type: 'Bearer',
  };
}

function formBody(call: unknown[] | undefined): URLSearchParams {
  const init = call?.[1] as RequestInit | undefined;
  return new URLSearchParams(String(init?.body));
}

async function corruptBackups(): Promise<string[]> {
  return (await readdir(path.dirname(getCredentialsPath()))).filter((name) =>
    name.startsWith('credentials.json.corrupt-')
  );
}

let configHome: string;

beforeEach(async () => {
  configHome = await mkdtemp(path.join(tmpdir(), 'gt-oauth-test-'));
  process.env.XDG_CONFIG_HOME = configHome;
});

afterEach(async () => {
  vi.restoreAllMocks();
  await rm(configHome, { recursive: true, force: true });
  delete process.env.XDG_CONFIG_HOME;
  delete process.env.GT_API_URL;
  delete process.env.GT_AUTH_URL;
});

describe('OAuth credential storage', () => {
  it('writes a versioned credential file with owner-only permissions', async () => {
    await writeOAuthTokens(tokens, authBaseUrl);

    expect(await readOAuthTokens(authBaseUrl)).toEqual(tokens);
    expect(JSON.parse(await readFile(getCredentialsPath(), 'utf8'))).toEqual({
      version: 2,
      servers: { [authBaseUrl]: { tokens } },
    });
    if (process.platform !== 'win32') {
      expect((await stat(getCredentialsPath())).mode & 0o777).toBe(0o600);
    }
  });

  it('keeps credentials for different authorization servers apart', async () => {
    await writeOAuthTokens(tokens, authBaseUrl);
    await writeOAuthTokens(
      { ...tokens, accessToken: 'dev-access' },
      'http://localhost:3000/api/auth'
    );

    expect((await readOAuthTokens(authBaseUrl))?.accessToken).toBe('access-1');
    expect(
      (await readOAuthTokens('http://localhost:3000/api/auth'))?.accessToken
    ).toBe('dev-access');
  });

  it('atomically replaces rotated refresh tokens', async () => {
    await writeOAuthTokens(tokens, authBaseUrl);
    await writeOAuthTokens(
      { ...tokens, refreshToken: 'refresh-2' },
      authBaseUrl
    );

    expect((await readOAuthTokens(authBaseUrl))?.refreshToken).toBe(
      'refresh-2'
    );
  });

  it('removes the file once the last server is logged out', async () => {
    await writeOAuthTokens(tokens, authBaseUrl);

    await deleteOAuthTokens(authBaseUrl);

    expect(await readOAuthTokens(authBaseUrl)).toBeUndefined();
    await expect(stat(getCredentialsPath())).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('ignores the client registration older files stored', async () => {
    await writeOAuthTokens(tokens, authBaseUrl);
    const stored = JSON.parse(await readFile(getCredentialsPath(), 'utf8'));
    stored.servers[authBaseUrl].client = {
      client_id: 'client-1',
      redirect_uri: 'http://127.0.0.1/callback',
    };
    await writeFile(getCredentialsPath(), JSON.stringify(stored), 'utf8');

    expect(await readOAuthTokens(authBaseUrl)).toEqual(tokens);
  });

  it('sets a malformed file aside and reads as logged out', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    await writeOAuthTokens(tokens, authBaseUrl);
    await writeFile(getCredentialsPath(), '{not json', 'utf8');

    expect(await readOAuthTokens(authBaseUrl)).toBeUndefined();
    expect(await corruptBackups()).toHaveLength(1);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it('sets a malformed file aside when replacing credentials', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    await writeOAuthTokens(tokens, authBaseUrl);
    await writeFile(getCredentialsPath(), '{not json', 'utf8');

    await writeOAuthTokens({ ...tokens, accessToken: 'access-2' }, authBaseUrl);

    expect((await readOAuthTokens(authBaseUrl))?.accessToken).toBe('access-2');
    const [backup] = await corruptBackups();
    expect(backup).toBeDefined();
    expect(
      await readFile(
        path.join(path.dirname(getCredentialsPath()), backup),
        'utf8'
      )
    ).toBe('{not json');
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain(backup);
  });

  it('still propagates filesystem errors when replacing credentials', async () => {
    if (process.platform === 'win32' || process.getuid?.() === 0) return;
    await writeOAuthTokens(tokens, authBaseUrl);
    await chmod(getCredentialsPath(), 0o000);

    await expect(writeOAuthTokens(tokens, authBaseUrl)).rejects.toThrow(
      /EACCES|EPERM/
    );
    expect(await corruptBackups()).toEqual([]);
  });

  it('sets the retired version 1 layout aside', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    await writeOAuthTokens(tokens, authBaseUrl);
    await writeFile(
      getCredentialsPath(),
      JSON.stringify({ version: 1, tokens: {} }),
      'utf8'
    );

    expect(await readOAuthTokens(authBaseUrl)).toBeUndefined();
    expect(await corruptBackups()).toHaveLength(1);
  });
});

describe('PKCE and authorization URL', () => {
  it('derives the S256 challenge from the verifier (RFC 7636 appendix B)', () => {
    expect(
      createPkcePair('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    ).toEqual({
      codeVerifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
      codeChallenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    });
  });

  it('generates a fresh 43-character verifier by default', () => {
    const first = createPkcePair();
    const second = createPkcePair();
    expect(first.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.codeVerifier).not.toBe(second.codeVerifier);
  });

  it('builds the authorize URL with PKCE, state, resource, and the CLI scopes', () => {
    const url = new URL(
      buildAuthorizationUrl({
        authBaseUrl,
        clientId: 'client-1',
        redirectUri: 'http://127.0.0.1:4242/callback',
        codeChallenge: 'challenge',
        state: 'state-1',
        apiResource,
      })
    );

    expect(url.origin + url.pathname).toBe(`${authBaseUrl}/oauth2/authorize`);
    expect(Object.fromEntries(url.searchParams)).toEqual({
      response_type: 'code',
      client_id: 'client-1',
      redirect_uri: 'http://127.0.0.1:4242/callback',
      scope: OAUTH_SCOPE,
      state: 'state-1',
      code_challenge: 'challenge',
      code_challenge_method: 'S256',
      resource: apiResource,
    });
  });

  it('never requests API key management scopes', () => {
    expect(OAUTH_SCOPE.split(' ')).not.toContain('project:api_keys:write');
    expect(OAUTH_SCOPE.split(' ')).toContain('offline_access');
  });

  it('serializes the API resource as a URL href', () => {
    process.env.GT_API_URL = 'https://api.example';
    expect(getApiResource()).toBe('https://api.example/');
  });
});

describe('authorization code exchange', () => {
  it('posts the PKCE verifier, redirect URI, and resource as a public client', async () => {
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(tokenResponse('access-2', 'refresh-2')));

    const result = await exchangeAuthorizationCode({
      authBaseUrl,
      fetch: fetchImplementation,
      clientId: 'client-1',
      code: 'code-1',
      codeVerifier: 'verifier-1',
      redirectUri: 'http://127.0.0.1:4242/callback',
      apiResource,
    });

    expect(result.accessToken).toBe('access-2');
    expect(fetchImplementation.mock.calls[0][0]).toBe(
      `${authBaseUrl}/oauth2/token`
    );
    expect(
      Object.fromEntries(formBody(fetchImplementation.mock.calls[0]))
    ).toEqual({
      grant_type: 'authorization_code',
      client_id: 'client-1',
      code: 'code-1',
      code_verifier: 'verifier-1',
      redirect_uri: 'http://127.0.0.1:4242/callback',
      resource: apiResource,
    });
  });

  it('stores tokens that omit scope and refresh_token so they read back', async () => {
    const response = tokenResponse('access-2', 'unused');
    delete response.scope;
    delete response.refresh_token;

    const result = await exchangeAuthorizationCode({
      authBaseUrl,
      fetch: vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(response)),
      clientId: 'client-1',
      code: 'code-1',
      codeVerifier: 'verifier-1',
      redirectUri: 'http://127.0.0.1:4242/callback',
      apiResource,
    });
    await writeOAuthTokens(result, authBaseUrl);

    expect(result.scope).toBe(OAUTH_SCOPE);
    expect(await readOAuthTokens(authBaseUrl)).toMatchObject({
      accessToken: 'access-2',
      refreshToken: '',
      scope: OAUTH_SCOPE,
    });
  });

  it('explains expired or reused codes', async () => {
    await expect(
      exchangeAuthorizationCode({
        authBaseUrl,
        fetch: vi
          .fn<typeof fetch>()
          .mockResolvedValue(jsonResponse({ error: 'invalid_grant' }, 400)),
        clientId: 'client-1',
        code: 'code-1',
        codeVerifier: 'verifier-1',
        redirectUri: 'http://127.0.0.1:4242/callback',
        apiResource,
      })
    ).rejects.toThrow('expired or was already used');
  });
});

describe('login', () => {
  it('opens the browser as the seeded client, receives the loopback callback, and stores tokens', async () => {
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(tokenResponse('access-2', 'refresh-2'))
      );
    const openBrowser = vi.fn(async (url: string) => {
      const authorize = new URL(url);
      const redirect = new URL(authorize.searchParams.get('redirect_uri')!);
      redirect.searchParams.set('code', 'code-1');
      redirect.searchParams.set('state', authorize.searchParams.get('state')!);
      // Simulate the browser following the provider redirect back to the CLI.
      void fetch(redirect);
    });

    const result = await login({
      authBaseUrl,
      apiResource,
      fetch: fetchImplementation,
      openBrowser,
      timeoutMs: 5_000,
    });

    expect(result.accessToken).toBe('access-2');
    expect((await readOAuthTokens(authBaseUrl))?.refreshToken).toBe(
      'refresh-2'
    );
    // Only the token exchange hit the provider; there is no registration step.
    expect(fetchImplementation).toHaveBeenCalledTimes(1);
    const authorizeUrl = new URL(openBrowser.mock.calls[0][0]);
    expect(authorizeUrl.searchParams.get('client_id')).toBe(OAUTH_CLIENT_ID);
    expect(authorizeUrl.searchParams.get('redirect_uri')).toMatch(
      /^http:\/\/127\.0\.0\.1:\d+\/callback$/
    );
    const exchange = Object.fromEntries(
      formBody(fetchImplementation.mock.calls[0])
    );
    expect(exchange.redirect_uri).toBe(
      authorizeUrl.searchParams.get('redirect_uri')
    );
    expect(exchange.code).toBe('code-1');
    expect(exchange.code_verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('rejects a callback whose state does not match', async () => {
    const fetchImplementation = vi.fn<typeof fetch>();
    const openBrowser = vi.fn(async (url: string) => {
      const redirect = new URL(new URL(url).searchParams.get('redirect_uri')!);
      redirect.searchParams.set('code', 'code-1');
      redirect.searchParams.set('state', 'forged');
      void fetch(redirect);
    });

    await expect(
      login({
        authBaseUrl,
        apiResource,
        fetch: fetchImplementation,
        openBrowser,
      })
    ).rejects.toThrow('state mismatch');
    expect(fetchImplementation).not.toHaveBeenCalled();
    expect(await readOAuthTokens(authBaseUrl)).toBeUndefined();
  });

  it('handles a callback that arrives before the browser launcher returns', async () => {
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(tokenResponse('access-2', 'refresh-2'))
      );
    const openBrowser = vi.fn(async (url: string) => {
      const authorize = new URL(url);
      const redirect = new URL(authorize.searchParams.get('redirect_uri')!);
      redirect.searchParams.set('code', 'code-1');
      redirect.searchParams.set('state', authorize.searchParams.get('state')!);
      const response = await fetch(redirect);
      expect(response.status).toBe(200);
    });

    const result = await login({
      authBaseUrl,
      apiResource,
      fetch: fetchImplementation,
      openBrowser,
      timeoutMs: 5_000,
    });

    expect(result.accessToken).toBe('access-2');
  });

  it('closes the loopback server when publishing the URL fails', async () => {
    let redirectUri = '';

    await expect(
      login({
        authBaseUrl,
        apiResource,
        fetch: vi.fn<typeof fetch>(),
        openBrowser: vi.fn(),
        onAuthorizationUrl: (url) => {
          redirectUri = new URL(url).searchParams.get('redirect_uri')!;
          throw new Error('cannot print');
        },
      })
    ).rejects.toThrow('cannot print');
    await expect(fetch(redirectUri)).rejects.toThrow();
  });

  it('reports access_denied from the provider', async () => {
    const openBrowser = vi.fn(async (url: string) => {
      const authorize = new URL(url);
      const redirect = new URL(authorize.searchParams.get('redirect_uri')!);
      redirect.searchParams.set('error', 'access_denied');
      redirect.searchParams.set('state', authorize.searchParams.get('state')!);
      void fetch(redirect);
    });

    await expect(
      login({
        authBaseUrl,
        apiResource,
        fetch: vi.fn<typeof fetch>(),
        openBrowser,
      })
    ).rejects.toThrow('Sign in was denied in the browser');
  });

  it('times out when the browser never returns', async () => {
    await expect(
      login({
        authBaseUrl,
        apiResource,
        fetch: vi.fn<typeof fetch>(),
        openBrowser: vi.fn().mockResolvedValue(undefined),
        timeoutMs: 20,
      })
    ).rejects.toThrow('Timed out waiting for the browser to sign in');
  });

  it('uses the device grant with --no-browser and stores the polled tokens', async () => {
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(deviceCodeResponse()))
      .mockResolvedValueOnce(
        jsonResponse({ error: 'authorization_pending' }, 400)
      )
      .mockResolvedValueOnce(
        jsonResponse(tokenResponse('access-2', 'refresh-2'))
      );
    const openBrowser = vi.fn();
    const onDeviceCode = vi.fn();
    const sleep = vi.fn(async () => undefined);

    const result = await login({
      authBaseUrl,
      apiResource,
      fetch: fetchImplementation,
      noBrowser: true,
      openBrowser,
      onDeviceCode,
      sleep,
    });

    expect(result.accessToken).toBe('access-2');
    expect((await readOAuthTokens(authBaseUrl))?.refreshToken).toBe(
      'refresh-2'
    );
    expect(openBrowser).not.toHaveBeenCalled();
    expect(onDeviceCode).toHaveBeenCalledWith(deviceCode);
    expect(fetchImplementation.mock.calls[0][0]).toBe(
      `${authBaseUrl}/device/code`
    );
    expect(
      Object.fromEntries(formBody(fetchImplementation.mock.calls[0]))
    ).toEqual({
      client_id: OAUTH_CLIENT_ID,
      scope: OAUTH_SCOPE,
      resource: apiResource,
    });
    expect(
      Object.fromEntries(formBody(fetchImplementation.mock.calls[2]))
    ).toEqual({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      client_id: OAUTH_CLIENT_ID,
      device_code: 'device-1',
      resource: apiResource,
    });
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(5_000);
  });

  it('opens the verification URL when a browser is available but the loopback listener cannot bind', async () => {
    const loopback = await import('./loopback.js');
    vi.spyOn(loopback, 'startLoopbackServer').mockRejectedValueOnce(
      new Error('EADDRINUSE')
    );
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(deviceCodeResponse()))
      .mockResolvedValueOnce(
        jsonResponse(tokenResponse('access-2', 'refresh-2'))
      );
    const openBrowser = vi.fn().mockResolvedValue(undefined);

    await login({
      authBaseUrl,
      apiResource,
      fetch: fetchImplementation,
      openBrowser,
      sleep: async () => undefined,
    });

    expect(openBrowser).toHaveBeenCalledWith(
      deviceCode.verificationUriComplete
    );
  });

  it('signs in over a corrupt credentials file and keeps a backup', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    await writeOAuthTokens(tokens, authBaseUrl);
    await writeFile(getCredentialsPath(), '{not json', 'utf8');
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse(deviceCodeResponse()))
      .mockResolvedValueOnce(
        jsonResponse(tokenResponse('access-2', 'refresh-2'))
      );

    await login({
      authBaseUrl,
      apiResource,
      fetch: fetchImplementation,
      noBrowser: true,
      onDeviceCode: () => undefined,
      sleep: async () => undefined,
    });

    expect((await readOAuthTokens(authBaseUrl))?.accessToken).toBe('access-2');
    expect(await corruptBackups()).toHaveLength(1);
  });
});

describe('device authorization grant', () => {
  it('surfaces provider errors when requesting a code', async () => {
    await expect(
      requestDeviceCode({
        authBaseUrl,
        apiResource,
        fetch: vi
          .fn<typeof fetch>()
          .mockResolvedValue(
            jsonResponse({ error: 'unauthorized_client' }, 400)
          ),
      })
    ).rejects.toThrow('does not recognize the gt CLI');
  });

  it('backs off on slow_down and stops on a terminal error', async () => {
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(jsonResponse({ error: 'slow_down' }, 400))
      .mockResolvedValueOnce(jsonResponse({ error: 'access_denied' }, 400));
    const sleep = vi.fn(async (_milliseconds: number) => undefined);

    await expect(
      pollDeviceToken({
        authBaseUrl,
        apiResource,
        deviceCode,
        fetch: fetchImplementation,
        sleep,
      })
    ).rejects.toThrow('Sign in was denied in the browser');
    expect(sleep.mock.calls.map(([ms]) => ms)).toEqual([5_000, 10_000]);
  });

  it('gives up once the code expires', async () => {
    let clock = 0;
    await expect(
      pollDeviceToken({
        authBaseUrl,
        apiResource,
        deviceCode: { ...deviceCode, expiresIn: 12 },
        fetch: vi
          .fn<typeof fetch>()
          .mockImplementation(async () =>
            jsonResponse({ error: 'authorization_pending' }, 400)
          ),
        now: () => clock,
        sleep: async (ms) => {
          clock += ms;
        },
      })
    ).rejects.toThrow('expired before it was approved');
  });
});

describe('OAuth session operations', () => {
  it('reports expired login when refresh is rejected with invalid_grant', async () => {
    await writeOAuthTokens({ ...tokens, expiresAt: 0 }, authBaseUrl);

    await expect(
      refreshOAuthTokens({
        authBaseUrl,
        fetch: vi
          .fn<typeof fetch>()
          .mockResolvedValue(jsonResponse({ error: 'invalid_grant' }, 400)),
      })
    ).rejects.toThrow('Your login expired. Run `gt login` to sign in again');
  });

  it('does not mistake a 401 invalid_client for an expired login', async () => {
    await writeOAuthTokens({ ...tokens, expiresAt: 0 }, authBaseUrl);

    await expect(
      refreshOAuthTokens({
        authBaseUrl,
        fetch: vi
          .fn<typeof fetch>()
          .mockResolvedValue(jsonResponse({ error: 'invalid_client' }, 401)),
      })
    ).rejects.toThrow('does not recognize the gt CLI');
    expect((await readOAuthTokens(authBaseUrl))?.refreshToken).toBe(
      'refresh-1'
    );
  });

  it('reports the HTTP status when refresh fails for another reason', async () => {
    await writeOAuthTokens({ ...tokens, expiresAt: 0 }, authBaseUrl);

    await expect(
      refreshOAuthTokens({
        authBaseUrl,
        fetch: vi
          .fn<typeof fetch>()
          .mockResolvedValue(new Response('<html>', { status: 503 })),
      })
    ).rejects.toThrow('Could not refresh your login (HTTP 503)');
    expect((await readOAuthTokens(authBaseUrl))?.refreshToken).toBe(
      'refresh-1'
    );
  });

  it('reports expired login when refresh fails with a non-JSON response', async () => {
    await writeOAuthTokens({ ...tokens, expiresAt: 0 }, authBaseUrl);

    await expect(
      refreshOAuthTokens({
        authBaseUrl,
        fetch: vi
          .fn<typeof fetch>()
          .mockResolvedValue(new Response(null, { status: 401 })),
      })
    ).rejects.toThrow('Your login expired. Run `gt login` to sign in again');
  });

  it('persists refresh-token rotation before returning the new access token', async () => {
    await writeOAuthTokens({ ...tokens, expiresAt: 0 }, authBaseUrl);
    let releaseRefresh!: (response: Response) => void;
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockReturnValueOnce(
        new Promise<Response>((resolve) => {
          releaseRefresh = resolve;
        })
      );

    await expect(
      refreshOAuthTokens({ authBaseUrl, fetch: fetchImplementation })
    ).rejects.toThrow('Your login expired');

    const concurrent = Promise.all([
      getValidAccessToken({ authBaseUrl, fetch: fetchImplementation }),
      refreshOAuthTokens({ authBaseUrl, fetch: fetchImplementation }),
      getValidAccessToken({ authBaseUrl, fetch: fetchImplementation }),
    ]);
    await vi.waitFor(() =>
      expect(fetchImplementation).toHaveBeenCalledTimes(2)
    );
    expect((await readOAuthTokens(authBaseUrl))?.refreshToken).toBe(
      'refresh-1'
    );
    releaseRefresh(jsonResponse(tokenResponse('access-2', 'refresh-2')));
    const [first, refreshed, second] = await concurrent;

    expect(first).toBe('access-2');
    expect(second).toBe('access-2');
    expect(refreshed.accessToken).toBe('access-2');
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    expect((await readOAuthTokens(authBaseUrl))?.refreshToken).toBe(
      'refresh-2'
    );
    expect(
      Object.fromEntries(formBody(fetchImplementation.mock.calls[1]))
    ).toEqual({
      client_id: OAUTH_CLIENT_ID,
      grant_type: 'refresh_token',
      refresh_token: 'refresh-1',
    });
  });

  it('creates a provider that reads lazily and reports a missing login', async () => {
    process.env.GT_AUTH_URL = authBaseUrl;
    const provider = createUserTokenProvider();

    await expect(provider.getAccessToken()).rejects.toThrow(
      'Run `gt login` to sign in'
    );
    await writeOAuthTokens(tokens, authBaseUrl);
    await expect(provider.getAccessToken()).resolves.toBe('access-1');
  });

  it('returns the cached access token while it is still fresh', async () => {
    await writeOAuthTokens(tokens, authBaseUrl);
    const fetchImplementation = vi.fn<typeof fetch>();

    await expect(
      getValidAccessToken({ authBaseUrl, fetch: fetchImplementation })
    ).resolves.toBe('access-1');
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it('preserves the refresh token when a provider does not rotate it', async () => {
    await writeOAuthTokens(tokens, authBaseUrl);
    const response = tokenResponse('access-2', 'unused');
    delete response.refresh_token;

    await refreshOAuthTokens({
      authBaseUrl,
      fetch: vi.fn<typeof fetch>().mockResolvedValue(jsonResponse(response)),
    });

    expect(await readOAuthTokens(authBaseUrl)).toMatchObject({
      refreshToken: 'refresh-1',
      scope: tokens.scope,
    });
  });

  it('revokes the refresh token and removes local tokens on logout', async () => {
    await writeOAuthTokens(tokens, authBaseUrl);
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(null, { status: 200 }));

    await logout({ authBaseUrl, fetch: fetchImplementation });

    expect(await readOAuthTokens(authBaseUrl)).toBeUndefined();
    expect(fetchImplementation.mock.calls[0][0]).toBe(
      `${authBaseUrl}/oauth2/revoke`
    );
    expect(
      Object.fromEntries(formBody(fetchImplementation.mock.calls[0]))
    ).toEqual({
      client_id: OAUTH_CLIENT_ID,
      token: 'refresh-1',
      token_type_hint: 'refresh_token',
    });
  });

  it('warns when the server does not revoke the session but still signs out locally', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    await writeOAuthTokens(tokens, authBaseUrl);

    await logout({
      authBaseUrl,
      fetch: vi
        .fn<typeof fetch>()
        .mockResolvedValue(new Response(null, { status: 500 })),
    });

    expect(await readOAuthTokens(authBaseUrl)).toBeUndefined();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain(
      'did not revoke the session (HTTP 500)'
    );
  });

  it('signs out locally without revoking when the credentials file is corrupt', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined);
    await writeOAuthTokens(tokens, authBaseUrl);
    await writeFile(getCredentialsPath(), '{not json', 'utf8');
    const fetchImplementation = vi.fn<typeof fetch>();

    await logout({ authBaseUrl, fetch: fetchImplementation });

    expect(fetchImplementation).not.toHaveBeenCalled();
    expect(await readOAuthTokens(authBaseUrl)).toBeUndefined();
    expect(await corruptBackups()).toHaveLength(1);
    expect(warn.mock.calls[0][0]).toContain('have been reset');
  });

  it('refreshes and returns userinfo for whoami', async () => {
    await writeOAuthTokens({ ...tokens, expiresAt: 0 }, authBaseUrl);
    const fetchImplementation = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        jsonResponse(tokenResponse('access-2', 'refresh-2'))
      )
      .mockResolvedValueOnce(
        jsonResponse({ sub: 'user-1', email: 'dev@example.com', name: 'Dev' })
      );

    await expect(
      whoAmI({ authBaseUrl, fetch: fetchImplementation })
    ).resolves.toEqual({
      sub: 'user-1',
      email: 'dev@example.com',
      name: 'Dev',
    });
    expect(fetchImplementation.mock.calls[1][0]).toBe(
      `${authBaseUrl}/oauth2/userinfo`
    );
    expect(fetchImplementation.mock.calls[1][1]?.headers).toEqual({
      Authorization: 'Bearer access-2',
    });
  });
});
