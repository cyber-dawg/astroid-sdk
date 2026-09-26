/**
 * Session management and automatic token refresh for `@astroid/auth`.
 *
 * @packageDocumentation
 */

import { AuthenticationError } from '@astroid/errors';
import type { AuthTokens } from '@astroid/types';
import type { HttpClient, Middleware, PreparedRequest } from '@astroid/core';

/** Custom storage interface for persisting session tokens (e.g., localStorage). */
export interface TokenStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

/** Options for constructing a {@link SessionManager}. */
export interface SessionManagerConfig {
  accessToken?: string;
  refreshToken?: string;
  storage?: TokenStorage;
  storageKeyPrefix?: string;
  bufferSeconds?: number;
  onTokenUpdate?: (tokens: AuthTokens) => void | Promise<void>;
}

/** Standard JWT payload claims. */
export interface JwtPayload {
  exp?: number;
  iat?: number;
  sub?: string;
  [key: string]: unknown;
}

/**
 * Decode a base64 / base64url string without external dependencies.
 */
function decodeBase64(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  if (typeof atob === 'function') {
    return atob(base64);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(base64, 'base64').toString('utf-8');
  }
  throw new Error('No base64 decoding environment available');
}

/**
 * Parse a JWT string and extract its decoded payload object.
 * Returns null if the token is malformed or unparseable.
 */
export function parseJwt(token: string | undefined): JwtPayload | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const payloadJson = decodeBase64(parts[1]!);
    return JSON.parse(payloadJson) as JwtPayload;
  } catch {
    return null;
  }
}

/**
 * Extract the expiration timestamp (`exp` in seconds) from a JWT token.
 * Returns null if the claim is missing or unparseable.
 */
export function getTokenExpiration(token: string | undefined): number | null {
  if (!token) return null;
  const payload = parseJwt(token);
  return typeof payload?.exp === 'number' ? payload.exp : null;
}

/**
 * Check if a token is expired or close to expiration (within bufferSeconds).
 */
export function isTokenExpired(token: string | undefined, bufferSeconds = 30): boolean {
  if (!token) return true;
  const exp = getTokenExpiration(token);
  if (exp === null) return false;
  const now = Math.floor(Date.now() / 1000);
  return now + bufferSeconds >= exp;
}

/**
 * Manages token lifecycles, persistence, and concurrent token refresh queuing.
 */
export class SessionManager {
  private accessToken?: string;
  private refreshToken?: string;
  private readonly storage?: TokenStorage;
  private readonly prefix: string;
  private readonly bufferSeconds: number;
  private readonly onTokenUpdate?: (tokens: AuthTokens) => void | Promise<void>;
  private activeRefreshPromise: Promise<AuthTokens> | null = null;

  constructor(config: SessionManagerConfig = {}) {
    this.accessToken = config.accessToken;
    this.refreshToken = config.refreshToken;
    this.storage = config.storage;
    this.prefix = config.storageKeyPrefix ?? 'astroid_auth_';
    this.bufferSeconds = config.bufferSeconds ?? 30;
    this.onTokenUpdate = config.onTokenUpdate;
  }

  /** The active access token. */
  getAccessToken(): string | undefined {
    return this.accessToken;
  }

  /** The active refresh token. */
  getRefreshToken(): string | undefined {
    return this.refreshToken;
  }

  /**
   * Update active tokens and persist them to storage if configured.
   */
  async setTokens(tokens: { accessToken: string; refreshToken?: string }): Promise<void> {
    this.accessToken = tokens.accessToken;
    if (tokens.refreshToken !== undefined) {
      this.refreshToken = tokens.refreshToken;
    }

    if (this.storage) {
      try {
        await this.storage.setItem(`${this.prefix}access_token`, tokens.accessToken);
        if (tokens.refreshToken) {
          await this.storage.setItem(`${this.prefix}refresh_token`, tokens.refreshToken);
        }
      } catch (err) {
        // Storage quota exceptions should not crash token adoption
        // eslint-disable-next-line no-console
        console.warn('Failed to persist tokens to storage:', err);
      }
    }

    if (this.onTokenUpdate) {
      try {
        const exp = getTokenExpiration(tokens.accessToken);
        const now = Math.floor(Date.now() / 1000);
        const expiresIn = exp ? Math.max(0, exp - now) : 3600;
        await this.onTokenUpdate({
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken ?? this.refreshToken ?? '',
          expiresIn,
          tokenType: 'Bearer',
        });
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn('Failed to execute onTokenUpdate callback:', err);
      }
    }
  }

  /**
   * Clear active credentials from memory and storage securely.
   */
  async clearTokens(): Promise<void> {
    this.accessToken = undefined;
    this.refreshToken = undefined;

    if (this.storage) {
      try {
        await this.storage.removeItem(`${this.prefix}access_token`);
        await this.storage.removeItem(`${this.prefix}refresh_token`);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.warn('Failed to clear tokens from storage:', err);
      }
    }
  }

  /** Check if the current access token is expired or close to expiration. */
  isAccessTokenExpired(bufferSeconds = this.bufferSeconds): boolean {
    return isTokenExpired(this.accessToken, bufferSeconds);
  }

  /** Check if the current refresh token is expired or close to expiration. */
  isRefreshTokenExpired(bufferSeconds = this.bufferSeconds): boolean {
    return isTokenExpired(this.refreshToken, bufferSeconds);
  }

  /**
   * Queue mechanism for concurrent refresh calls:
   * Ensures only one refresh request is executed simultaneously when multiple calls
   * encounter an expired token concurrently.
   */
  async refreshSession(
    refreshFn: (refreshToken: string) => Promise<AuthTokens>
  ): Promise<AuthTokens> {
    if (this.activeRefreshPromise) {
      return this.activeRefreshPromise;
    }

    if (!this.refreshToken || this.isRefreshTokenExpired(0)) {
      await this.clearTokens();
      throw new AuthenticationError('Refresh token is missing or expired', {
        code: 'TOKEN_EXPIRED',
        status: 401,
      });
    }

    const tokenToUse = this.refreshToken;

    this.activeRefreshPromise = (async () => {
      try {
        const tokens = await refreshFn(tokenToUse);
        await this.setTokens(tokens);
        return tokens;
      } catch (err) {
        await this.clearTokens();
        if (err instanceof AuthenticationError) {
          throw err;
        }
        throw new AuthenticationError('Failed to refresh session token', {
          code: 'TOKEN_EXPIRED',
          status: 401,
          cause: err,
        });
      } finally {
        this.activeRefreshPromise = null;
      }
    })();

    return this.activeRefreshPromise;
  }

  /** True while a refresh started by {@link refreshSession} is in flight. */
  isRefreshing(): boolean {
    return this.activeRefreshPromise !== null;
  }

  /**
   * Resolve once any in-flight refresh settles; resolves immediately when
   * idle. A failed refresh is swallowed here — waiting callers surface the
   * resulting authentication error through the normal 401 path instead of
   * duplicating it for every queued request.
   */
  async waitForRefresh(): Promise<void> {
    const pending = this.activeRefreshPromise;
    if (!pending) return;
    try {
      await pending;
    } catch {
      // The failed refresh already cleared tokens; the caller's own request
      // will produce the authoritative authentication error.
    }
  }
}

/**
 * Wire a {@link SessionManager} to an {@link HttpClient} so that 401
 * responses trigger automatic token refresh and the failed request is
 * retried with the new credentials.
 *
 * ```ts
 * import { SessionManager, wireSessionToHttpClient } from '@astroid/auth';
 *
 * const session = new SessionManager({ storage: localStorage });
 * const client = new Astroid({ baseUrl, apiKey });
 * wireSessionToHttpClient(client, session, refreshFn);
 * ```
 */
export function wireSessionToHttpClient(
  client: HttpClient,
  sessionManager: SessionManager,
  refreshFn: (refreshToken: string) => Promise<AuthTokens>,
): void {
  client.set401Handler(async () => {
    try {
      await sessionManager.refreshSession(refreshFn);
      const token = sessionManager.getAccessToken();
      if (token) client.setAccessToken(token);
      return true;
    } catch {
      return false;
    }
  });
}

/**
 * Creates an SDK middleware interceptor that checks for token expiration
 * and automatically triggers queued session refresh before outgoing requests.
 */
export function createSessionMiddleware(
  sessionManager: SessionManager,
  refreshFn: (refreshToken: string) => Promise<AuthTokens>
): Middleware {
  return {
    name: 'session-auto-refresh',
    async onRequest(req: PreparedRequest): Promise<PreparedRequest> {
      // Do not intercept authentication endpoints to prevent cyclic calls
      if (
        req.url.includes('/auth/refresh') ||
        req.url.includes('/auth/login') ||
        req.url.includes('/auth/register')
      ) {
        return req;
      }

      if (sessionManager.getRefreshToken() && sessionManager.isAccessTokenExpired()) {
        try {
          const newTokens = await sessionManager.refreshSession(refreshFn);
          return {
            ...req,
            headers: {
              ...req.headers,
              authorization: `Bearer ${newTokens.accessToken}`,
            },
          };
        } catch (err) {
          if (err instanceof AuthenticationError) {
            throw err;
          }
          throw new AuthenticationError('Session expired and token refresh failed', {
            code: 'TOKEN_EXPIRED',
            status: 401,
            cause: err,
          });
        }
      }

      return req;
    },
    async onError(error: unknown, _req: PreparedRequest): Promise<void> {
      if (error instanceof AuthenticationError && error.status === 401) {
        await sessionManager.clearTokens();
      }
    },
  };
}
