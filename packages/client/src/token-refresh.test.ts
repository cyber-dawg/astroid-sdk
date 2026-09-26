import { describe, it, expect, vi } from 'vitest';
import { AuthenticationError } from '@astroid/errors';
import type { PreparedRequest } from '@astroid/core';
import type { AuthTokens } from '@astroid/types';
import { SessionManager } from '@astroid/auth';
import { Astroid } from './index.js';
import { createTokenRefreshInterceptor } from './token-refresh.js';

/* -------------------------------------------------------------------------- */
/* Test helpers                                                                */
/* -------------------------------------------------------------------------- */

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function unauthorized(): Response {
  return new Response(
    JSON.stringify({ error: { message: 'Token expired', code: 'TOKEN_EXPIRED' } }),
    { status: 401, headers: { 'content-type': 'application/json' } },
  );
}

function makeRequest(url: string, authorization = 'Bearer stale'): PreparedRequest {
  return {
    method: 'GET',
    url,
    headers: { authorization },
    body: undefined,
    timeoutMs: 10_000,
    retryable: true,
    signal: undefined,
    options: { method: 'GET', path: url },
  };
}

const INITIAL_TOKENS: AuthTokens = {
  accessToken: 'initial_access',
  refreshToken: 'initial_refresh',
  expiresIn: 3600,
  tokenType: 'Bearer',
};

/* -------------------------------------------------------------------------- */
/* createTokenRefreshInterceptor — module unit tests                           */
/* -------------------------------------------------------------------------- */

describe('createTokenRefreshInterceptor', () => {
  it('handleUnauthorized returns false without refreshing when no refresh token is stored', async () => {
    const sessionManager = new SessionManager({ accessToken: 'stale_access' });
    const refresh = vi.fn();
    const interceptor = createTokenRefreshInterceptor({ sessionManager, refresh });

    const handled = await interceptor.handleUnauthorized(makeRequest('https://api.test/v1/wallets'));

    expect(handled).toBe(false);
    expect(refresh).not.toHaveBeenCalled();
  });

  it('handleUnauthorized refreshes once and signals a replay on success', async () => {
    const sessionManager = new SessionManager(INITIAL_TOKENS);
    const refresh = vi.fn().mockResolvedValue({
      accessToken: 'fresh_access',
      refreshToken: 'fresh_refresh',
      expiresIn: 3600,
      tokenType: 'Bearer',
    } satisfies AuthTokens);
    const interceptor = createTokenRefreshInterceptor({ sessionManager, refresh });

    const handled = await interceptor.handleUnauthorized(makeRequest('https://api.test/v1/wallets'));

    expect(handled).toBe(true);
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(refresh).toHaveBeenCalledWith('initial_refresh');
    expect(sessionManager.getAccessToken()).toBe('fresh_access');
  });

  it('handleUnauthorized returns false (no loop) when the refresh fails', async () => {
    const sessionManager = new SessionManager(INITIAL_TOKENS);
    const refresh = vi
      .fn()
      .mockRejectedValue(new AuthenticationError('refresh revoked', { code: 'TOKEN_EXPIRED' }));
    const interceptor = createTokenRefreshInterceptor({ sessionManager, refresh });

    const handled = await interceptor.handleUnauthorized(makeRequest('https://api.test/v1/wallets'));

    expect(handled).toBe(false);
    // Failed refresh clears credentials so subsequent 401s short-circuit.
    expect(sessionManager.getAccessToken()).toBeUndefined();
    expect(sessionManager.getRefreshToken()).toBeUndefined();

    // A second 401 does not attempt another refresh (loop prevention).
    const again = await interceptor.handleUnauthorized(makeRequest('https://api.test/v1/wallets'));
    expect(again).toBe(false);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('middleware passes requests through untouched when no refresh is active', async () => {
    const sessionManager = new SessionManager(INITIAL_TOKENS);
    const interceptor = createTokenRefreshInterceptor({ sessionManager, refresh: vi.fn() });
    const req = makeRequest('https://api.test/v1/wallets');

    const out = await interceptor.middleware.onRequest!(req);

    expect(out).toBe(req);
    expect(out.headers.authorization).toBe('Bearer stale');
  });

  it('middleware queues requests behind an active refresh and re-tags the token', async () => {
    const sessionManager = new SessionManager(INITIAL_TOKENS);
    const refresh = vi.fn().mockImplementation(async () => {
      await new Promise((r) => setTimeout(r, 40));
      await sessionManager.setTokens({
        accessToken: 'fresh_access',
        refreshToken: 'fresh_refresh',
      });
      return {
        accessToken: 'fresh_access',
        refreshToken: 'fresh_refresh',
        expiresIn: 3600,
        tokenType: 'Bearer',
      } satisfies AuthTokens;
    });
    const interceptor = createTokenRefreshInterceptor({ sessionManager, refresh });

    // Kick off a refresh as the 401 handler would (do not await it yet).
    const refreshing = interceptor.handleUnauthorized(makeRequest('https://api.test/v1/wallets'));
    expect(sessionManager.isRefreshing()).toBe(true);

    const queued = interceptor.middleware.onRequest!(
      makeRequest('https://api.test/v1/agents', 'Bearer stale'),
    );

    const [, out] = await Promise.all([refreshing, queued]);
    expect(out.headers.authorization).toBe('Bearer fresh_access');
    expect(sessionManager.isRefreshing()).toBe(false);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it('middleware never waits on auth endpoints (no self-deadlock on /auth/refresh)', async () => {
    const sessionManager = new SessionManager(INITIAL_TOKENS);
    const refresh = vi.fn().mockImplementation(async () => {
      await new Promise((r) => setTimeout(r, 30));
      return { ...INITIAL_TOKENS, accessToken: 'fresh_access' };
    });
    const interceptor = createTokenRefreshInterceptor({ sessionManager, refresh });

    const refreshing = interceptor.handleUnauthorized(makeRequest('https://api.test/v1/wallets'));
    expect(sessionManager.isRefreshing()).toBe(true);

    const authReq = makeRequest('https://api.test/v1/auth/refresh');
    const out = await interceptor.middleware.onRequest!(authReq);

    // Returned immediately — not held behind the in-flight refresh.
    expect(out).toBe(authReq);
    expect(out.headers.authorization).toBe('Bearer stale');
    await refreshing;
  });
});

/* -------------------------------------------------------------------------- */
/* End-to-end through the Astroid client                                       */
/* -------------------------------------------------------------------------- */

describe('Astroid token refresh integration', () => {
  it('queues a request issued mid-refresh and sends it with the fresh token (single refresh)', async () => {
    let refreshCalls = 0;
    let freshToken = false;

    const mockFetch = vi.fn().mockImplementation(async (url: string | URL, options?: RequestInit) => {
      const urlStr = url.toString();
      const headers = (options?.headers as Record<string, string>) ?? {};

      if (urlStr.includes('/auth/refresh')) {
        refreshCalls++;
        await new Promise((r) => setTimeout(r, 50));
        freshToken = true;
        return jsonResponse({
          accessToken: 'fresh_access',
          refreshToken: 'fresh_refresh',
          expiresIn: 3600,
          tokenType: 'Bearer',
        });
      }

      if (headers.authorization === 'Bearer fresh_access') {
        return jsonResponse({ data: { id: urlStr.split('/').pop(), ok: true } });
      }
      return unauthorized();
    });

    const client = new Astroid({
      accessToken: INITIAL_TOKENS.accessToken,
      refreshToken: INITIAL_TOKENS.refreshToken,
      baseUrl: 'https://api.test/v1',
      fetch: mockFetch as unknown as typeof fetch,
    });

    // First request triggers the 401 → refresh cycle.
    const first = client.wallets.get('w1');
    // Give the refresh time to start, then issue a second request mid-refresh.
    await new Promise((r) => setTimeout(r, 10));
    expect(client.sessionManager.isRefreshing()).toBe(true);
    const second = client.agents.get('a1');

    const [w1, a1] = await Promise.all([first, second]);

    expect(w1).toEqual({ id: 'w1', ok: true });
    expect(a1).toEqual({ id: 'a1', ok: true });
    // The queued request went out once, with the fresh token — one refresh total.
    expect(refreshCalls).toBe(1);
    expect(freshToken).toBe(true);
    expect(client.sessionManager.getAccessToken()).toBe('fresh_access');
  });

  it('failed refresh rejects queued requests without looping', async () => {
    let refreshCalls = 0;

    const mockFetch = vi.fn().mockImplementation(async (url: string | URL) => {
      const urlStr = url.toString();
      if (urlStr.includes('/auth/refresh')) {
        refreshCalls++;
        return new Response(
          JSON.stringify({ error: { message: 'Refresh revoked', code: 'TOKEN_INVALID' } }),
          { status: 401, headers: { 'content-type': 'application/json' } },
        );
      }
      return unauthorized();
    });

    const client = new Astroid({
      accessToken: INITIAL_TOKENS.accessToken,
      refreshToken: INITIAL_TOKENS.refreshToken,
      baseUrl: 'https://api.test/v1',
      fetch: mockFetch as unknown as typeof fetch,
    });

    const results = await Promise.allSettled([
      client.wallets.get('w1'),
      client.agents.get('a1'),
    ]);

    for (const result of results) {
      expect(result.status).toBe('rejected');
      if (result.status === 'rejected') {
        expect(result.reason).toBeInstanceOf(AuthenticationError);
      }
    }
    // Single-flight: both 401s shared one refresh attempt.
    expect(refreshCalls).toBe(1);
    expect(client.sessionManager.getAccessToken()).toBeUndefined();
    expect(client.sessionManager.getRefreshToken()).toBeUndefined();
  });
});
