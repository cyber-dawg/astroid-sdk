/**
 * `@astroid/client` — token refresh interceptor (issue #103).
 *
 * A refresh lifecycle has two halves:
 *
 * 1. **Reactive** — a `401 Unauthorized` response triggers a single, queued
 *    token refresh via the {@link SessionManager} (single-flight: concurrent
 *    401s share one refresh) and, on success, the `HttpClient` replays the
 *    original request exactly once.
 * 2. **Proactive** — requests issued *while* a refresh is in flight are held
 *    back until it settles, then re-tagged with the fresh access token, so
 *    they don't burn a doomed round-trip (and a refresh) on a stale token.
 *
 * Loop safety: the replay is guarded by the `HttpClient`'s per-request
 * `_is401Retry` flag (a replayed request that401s again fails instead of
 * re-triggering the interceptor), and a failed refresh clears the stored
 * tokens so subsequent 401s short-circuit without another refresh attempt.
 *
 * @module
 */

import type { SessionManager } from '@astroid/auth';
import type { Middleware, PreparedRequest } from '@astroid/core';
import type { AuthTokens } from '@astroid/types';

/** Options for {@link createTokenRefreshInterceptor}. */
export interface TokenRefreshInterceptorOptions {
  /** Session owning the token store and the single-flight refresh queue. */
  sessionManager: SessionManager;
  /** Exchanges a refresh token for fresh tokens (e.g. `POST /auth/refresh`). */
  refresh: (refreshToken: string) => Promise<AuthTokens>;
  /**
   * URL fragments that must never wait on or trigger a refresh — the auth
   * endpoints themselves (waiting on `/auth/refresh` would deadlock).
   * Defaults to the standard auth routes.
   */
  skipPaths?: readonly string[];
}

/** Handler signature accepted by `HttpClient.set401Handler`. */
export type UnauthorizedHandler = (req: PreparedRequest) => Promise<boolean>;

/** The pair of hooks that make up the interceptor. */
export interface TokenRefreshInterceptor {
  /** 401 handler: refresh on demand; `true` replays the original request. */
  handleUnauthorized: UnauthorizedHandler;
  /** Middleware that queues outbound requests behind an in-flight refresh. */
  middleware: Middleware;
}

/** Auth endpoints excluded from refresh queueing (mirrors the session middleware). */
const DEFAULT_SKIP_PATHS: readonly string[] = [
  '/auth/refresh',
  '/auth/login',
  '/auth/register',
];

/**
 * Build the token refresh interceptor.
 *
 * Wire `handleUnauthorized` to `HttpClient.set401Handler` and register
 * `middleware` on the client so concurrent requests queue behind an active
 * refresh instead of racing it with a stale token.
 *
 * ```ts
 * const interceptor = createTokenRefreshInterceptor({ sessionManager, refresh });
 * client.use(interceptor.middleware);
 * client.set401Handler(interceptor.handleUnauthorized);
 * ```
 */
export function createTokenRefreshInterceptor(
  options: TokenRefreshInterceptorOptions,
): TokenRefreshInterceptor {
  const { sessionManager, refresh } = options;
  const skipPaths = options.skipPaths ?? DEFAULT_SKIP_PATHS;

  const handleUnauthorized: UnauthorizedHandler = async () => {
    if (!sessionManager.getRefreshToken()) {
      return false;
    }
    try {
      // Single-flight: concurrent 401s join the same refresh promise.
      await sessionManager.refreshSession(refresh);
      return true;
    } catch {
      // Failed refresh already cleared tokens; let the original 401 error
      // propagate instead of looping.
      return false;
    }
  };

  const middleware: Middleware = {
    name: 'token-refresh-queue',
    async onRequest(req) {
      if (skipPaths.some((p) => req.url.includes(p))) return req;
      if (!sessionManager.isRefreshing()) return req;

      await sessionManager.waitForRefresh();

      // Re-tag the request with the fresh token minted while we waited.
      const token = sessionManager.getAccessToken();
      if (token) {
        req.headers['authorization'] = `Bearer ${token}`;
      }
      return req;
    },
  };

  return { handleUnauthorized, middleware };
}
