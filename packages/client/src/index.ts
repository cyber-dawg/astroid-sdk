/**
 * `@astroid/client` — the main SDK entry point.
 *
 * ```ts
 * import { Astroid } from '@astroid/client';
 *
 * const astroid = new Astroid({ apiKey: process.env.ASTROID_API_KEY! });
 *
 * // Resource namespaces:
 * const wallet = await astroid.wallets.create({ label: 'Ops', walletType: 'CUSTODIAL' });
 *
 * // AI-native intent:
 * const result = await astroid.ai.requestPayment({
 *   intent: 'Purchase OpenAI credits',
 *   amount: 150,
 *   asset: 'USDC',
 * });
 * ```
 *
 * The client owns a single {@link HttpClient} and hands it to every resource, so
 * a runtime token refresh (via {@link Astroid.setAccessToken}) is seen by all of
 * them at once.
 *
 * @packageDocumentation
 */

import {
  HttpClient,
  SDK_VERSION,
  type AstroidClientConfig as CoreClientConfig,
  type Middleware,
  type QueryValue,
} from '@astroid/core';
import type { PaginationParams } from '@astroid/types';
import { serializePaginationParams } from './pagination.js';
import { createCorrelationMiddleware } from './middleware/correlation.js';
import { createRateLimiterMiddleware } from './middleware/rate-limiter.js';
import { createLoggingMiddleware, type LoggingMiddlewareOptions } from './middleware/logging.js';
import { createErrorParserMiddleware } from './error-parser-middleware.js';
import { AgentResource } from '@astroid/agent';
import { AnalyticsResource } from '@astroid/analytics';
import { AuthResource, SessionManager, createSessionMiddleware } from '@astroid/auth';
import { BudgetResource } from '@astroid/budget';
import { NotificationResource } from '@astroid/notification';
import { PolicyResource } from '@astroid/policy';
import { TransactionResource } from '@astroid/transaction';
import { WalletResource } from '@astroid/wallet';
import { WebhookResource } from '@astroid/webhook';
import type {
  AuthTokens,
  EventHandlerMap,
  PaymentIntent,
  PaymentIntentResult,
  WebhookEventEnvelope,
  WebhookEventName,
} from '@astroid/types';
import { createErrorTranslatorMiddleware } from './middleware/error.js';
import { createTokenRefreshInterceptor } from './token-refresh.js';

/**
 * Configuration accepted by `new Astroid({ ... })`.
 *
 * Extends the core client config with shorthand retry options
 * (`retries` / `retryDelay`) for convenience.
 */
export interface AstroidClientConfig extends CoreClientConfig {
  /** Maximum number of retries after the first attempt (shorthand for `retry.maxRetries`). */
  retries?: number;
  /** Base retry delay in ms (shorthand for `retry.baseDelayMs`). */
  retryDelay?: number;
  /** Request/response logging hooks with automatic header redaction. */
  logging?: LoggingMiddlewareOptions;
  /**
   * Custom correlation/tracing headers applied to every outbound request
   * (issue #255). Shorthand for the core `tracingHeaders` option: use this to
   * stamp a fixed deployment- or tenant-level `X-Correlation-ID`, or to set the
   * `X-Request-ID` / `X-Astroid-Correlation-ID` header names with static values.
   * Per-request `options.headers`, `options.correlationId` and
   * `options.requestId` always take precedence.
   */
  tracingHeaders?: Record<string, string>;
}

/** The AI-native namespace: express intents, not low-level transfers. */
export class AiResource {
  constructor(private readonly client: HttpClient) {}

  /**
   * Submit a high-level financial intent. The backend orchestrates the whole
   * workflow — proposal, policy evaluation, risk scoring, transaction — and
   * returns a {@link PaymentIntentResult} whose `outcome` says what happened
   * (`executed`, `pending_approval`, `simulated`, or `rejected`), always with a
   * human-readable `explanation`.
   *
   * Set `simulateOnly: true` to force AI Simulation Mode (nothing is created).
   */
  async requestPayment(intent: PaymentIntent): Promise<PaymentIntentResult> {
    const res = await this.client.post<PaymentIntentResult>('/ai/request-payment', intent);
    return res.data;
  }

  /**
   * Simulate an intent without creating anything. Convenience wrapper over
   * {@link AiResource.requestPayment} with `simulateOnly` forced on.
   */
  async simulatePayment(intent: Omit<PaymentIntent, 'simulateOnly'>): Promise<PaymentIntentResult> {
    return this.requestPayment({ ...intent, simulateOnly: true });
  }
}

/** A listener for a specific event name, typed via {@link EventHandlerMap}. */
export type EventListener<K extends WebhookEventName> = EventHandlerMap[K];

/** Unsubscribe function returned by {@link Astroid.on}. */
export type Unsubscribe = () => void;

/**
 * A plugin extends the client at construction time. It receives the fully-built
 * {@link Astroid} instance and may register middleware, attach event listeners,
 * or hang extra helpers off it. Return value is ignored.
 */
export interface AstroidPlugin {
  name: string;
  install(client: Astroid): void;
}

/**
 * A minimal, fully-typed event emitter over the platform's webhook event names.
 * The client uses this so application code can react to events it feeds in
 * (e.g. from a webhook handler or a websocket) with the same names the backend
 * emits: `astroid.on('transaction.completed', tx => ...)`.
 */
class TypedEmitter {
  private readonly listeners = new Map<WebhookEventName, Set<(...args: never[]) => void>>();

  on<K extends WebhookEventName>(event: K, listener: EventListener<K>): Unsubscribe {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener as (...args: never[]) => void);
    return () => this.off(event, listener);
  }

  once<K extends WebhookEventName>(event: K, listener: EventListener<K>): Unsubscribe {
    const wrapped = ((data, envelope) => {
      off();
      (listener as (d: unknown, e: unknown) => void)(data, envelope);
    }) as EventListener<K>;
    const off = this.on(event, wrapped);
    return off;
  }

  off<K extends WebhookEventName>(event: K, listener: EventListener<K>): void {
    this.listeners.get(event)?.delete(listener as (...args: never[]) => void);
  }

  emit<K extends WebhookEventName>(event: WebhookEventEnvelope<K>): void {
    const set = this.listeners.get(event.event);
    if (!set) return;
    for (const listener of [...set]) {
      (listener as (d: unknown, e: unknown) => void)(event.data, event);
    }
  }

  removeAll(event?: WebhookEventName): void {
    if (event) this.listeners.delete(event);
    else this.listeners.clear();
  }
}

/**
 * The Astroid SDK client. Construct once and reuse; it is safe to share across
 * requests. Each resource namespace shares the one underlying {@link HttpClient},
 * so a token refresh or middleware registration is seen by all of them at once.
 */
export class Astroid {
  /** The SDK version, for diagnostics. */
  static readonly version = SDK_VERSION;

  /** The shared low-level HTTP client (escape hatch for un-wrapped calls). */
  readonly http: HttpClient;

  readonly sessionManager: SessionManager;
  readonly auth: AuthResource;
  readonly wallets: WalletResource;
  readonly agents: AgentResource;
  readonly policies: PolicyResource;
  readonly budgets: BudgetResource;
  readonly transactions: TransactionResource;
  readonly notifications: NotificationResource;
  readonly analytics: AnalyticsResource;
  readonly webhooks: WebhookResource;
  readonly ai: AiResource;

  private readonly emitter = new TypedEmitter();
  private readonly plugins: AstroidPlugin[] = [];

  constructor(config: AstroidClientConfig | HttpClient) {
    this.http = config instanceof HttpClient ? config : new HttpClient(normalizeConfig(config));

    const authConfig = this.http.config.auth;

    // If accessToken is a dynamic function, extract it as a token provider.
    const dynamicTokenProvider =
      !(config instanceof HttpClient) && typeof config.accessToken === 'function'
        ? config.accessToken
        : undefined;

    this.sessionManager = new SessionManager({
      accessToken: typeof authConfig.accessToken === 'string' ? authConfig.accessToken : undefined,
      refreshToken: authConfig.refreshToken,
      onTokenUpdate: authConfig.onTokenUpdate,
    });

    this.auth = new AuthResource(this.http, this.sessionManager);
    this.wallets = new WalletResource(this.http);
    this.agents = new AgentResource(this.http);
    this.policies = new PolicyResource(this.http);
    this.budgets = new BudgetResource(this.http);
    this.transactions = new TransactionResource(this.http);
    this.notifications = new NotificationResource(this.http);
    this.analytics = new AnalyticsResource(this.http);
    this.webhooks = new WebhookResource(this.http);
    this.ai = new AiResource(this.http);

    // Structured error translation: map Horizon and API error payloads to typed domain exceptions
    // (e.g. op_low_reserve → InsufficientFundsError, POLICY_VIOLATION → PolicyViolationError).
    // Installed by default so consumers get high-fidelity errors without manual middleware wiring.
    this.use(createErrorTranslatorMiddleware());

    // Token refresh interceptor (issue #103): a single-flight refresh shared
    // by all concurrent 401s, plus a middleware that queues requests issued
    // while a refresh is in flight so they don't race it with a stale token.
    const refreshTokens = async (refreshToken: string): Promise<AuthTokens> => {
      const res = await this.http.post<AuthTokens>('/auth/refresh', { refreshToken });
      this.setAccessToken(res.data.accessToken);
      return res.data;
    };

    this.use(
      createSessionMiddleware(this.sessionManager, refreshTokens),
    );

    const tokenRefresh = createTokenRefreshInterceptor({
      sessionManager: this.sessionManager,
      refresh: refreshTokens,
    });
    this.use(tokenRefresh.middleware);
    this.http.set401Handler(tokenRefresh.handleUnauthorized);

    // Wire up the dynamic token provider (called before every request;
    // the HttpClient deduplicates concurrent calls automatically).
    if (dynamicTokenProvider) {
      this.http.setTokenProvider(dynamicTokenProvider);
    }

    // Token-bucket rate limiting: throttle and queue outbound requests when
    // configured so agents never trip API gateway rate limits mid-workflow.
    const clientConfig = config instanceof HttpClient ? undefined : config;
    if (clientConfig?.rateLimit) {
      this.http.use(createRateLimiterMiddleware(clientConfig.rateLimit));
    }

    // Correlation ID + telemetry: every outbound request carries a
    // X-Astroid-Correlation-ID header and fires onRequest/onResponse hooks.
    // Static tracing headers from the config are honoured as defaults and are
    // overridden by per-request options.
    this.http.use(createCorrelationMiddleware(clientConfig?.telemetry, clientConfig?.tracingHeaders));

    // Request/response logging with header redaction (opt-in via config).
    if (clientConfig?.logging) {
      this.http.use(createLoggingMiddleware(clientConfig.logging));
    }

    // Auto-register the error parser middleware so all responses are routed
    // through the rich error mapping layer.
    this.http.use(createErrorParserMiddleware());
  }

  /** Register a request/response middleware. Returns `this` for chaining. */
  use(middleware: Middleware): this {
    this.http.use(middleware);
    return this;
  }

  /**
   * Install a plugin. The plugin's `install` is invoked immediately with this
   * client, so it can register middleware, attach listeners, or add helpers.
   * Returns `this` for chaining.
   */
  register(plugin: AstroidPlugin): this {
    this.plugins.push(plugin);
    plugin.install(this);
    return this;
  }

  /** The names of every installed plugin, in install order. */
  get installedPlugins(): readonly string[] {
    return this.plugins.map((p) => p.name);
  }

  /* -------------------------------- events -------------------------------- */

  /**
   * Subscribe to an event. Returns an unsubscribe function.
   *
   * ```ts
   * const off = astroid.on('transaction.completed', (tx) => console.log(tx.id));
   * // later: off();
   * ```
   *
   * The client does not open its own connection — feed it events from your
   * webhook handler (after {@link WebhookResource.constructEvent}) or a stream
   * via {@link Astroid.emit}, and they fan out to your typed listeners.
   */
  on<K extends WebhookEventName>(event: K, listener: EventListener<K>): Unsubscribe {
    return this.emitter.on(event, listener);
  }

  /** Subscribe to the next occurrence of an event only. */
  once<K extends WebhookEventName>(event: K, listener: EventListener<K>): Unsubscribe {
    return this.emitter.once(event, listener);
  }

  /** Remove a previously-registered listener. */
  off<K extends WebhookEventName>(event: K, listener: EventListener<K>): void {
    this.emitter.off(event, listener);
  }

  /** Dispatch an event envelope to all matching listeners. */
  emit<K extends WebhookEventName>(event: WebhookEventEnvelope<K>): void {
    this.emitter.emit(event);
  }

  /** Remove all listeners for one event, or (with no argument) for every event. */
  removeAllListeners(event?: WebhookEventName): void {
    this.emitter.removeAll(event);
  }

  /**
   * Update the bearer access token at runtime (e.g. after a refresh). All
   * resource namespaces pick it up immediately because they share one client.
   */
  setAccessToken(accessToken: string | undefined): void {
    this.http.setAccessToken(accessToken);
  }

  /**
   * Merge pagination parameters with arbitrary query parameters into a single
   * serialisable record, ready to pass as the `query` option of any request.
   */
  buildQuery(params: PaginationParams & Record<string, QueryValue>): Record<string, QueryValue> {
    return { ...serializePaginationParams(params), ...params };
  }
}

export default Astroid;

/** Normalise the shorthand `retries` / `retryDelay` options into core retry config. */
function normalizeConfig(config: AstroidClientConfig): CoreClientConfig {
  if (config.retries === undefined) return config;
  return {
    ...config,
    retry: {
      maxRetries: config.retries,
      baseDelayMs: config.retryDelay ?? 250,
      maxDelayMs: 8000,
    },
  };
}

// Re-export the resource classes and their param types so consumers can name
// them without reaching into individual packages.
export {
  AuthResource,
  SessionManager,
  createSessionMiddleware,
  parseJwt,
  isTokenExpired,
  getTokenExpiration,
  type TokenStorage,
  type SessionManagerConfig,
} from '@astroid/auth';
export { WalletResource, type WalletListParams } from '@astroid/wallet';
export { AgentResource, type AgentListParams, type AgentCursorListParams } from '@astroid/agent';
export { PolicyResource, type PolicyListParams } from '@astroid/policy';
export { BudgetResource, type BudgetListParams } from '@astroid/budget';
export { TransactionResource, type ProposalListParams } from '@astroid/transaction';
export { NotificationResource } from '@astroid/notification';
export { AnalyticsResource } from '@astroid/analytics';
export {
  WebhookResource,
  WebhookSignatureError,
  type WebhookListParams,
  type ConstructEventOptions,
} from '@astroid/webhook';

// Convenience re-exports of the most-used types and errors.
export {
  createRetryMiddleware,
  retryMiddleware,
  backoffDelay,
  isRetryableStatus,
  type Middleware,
  type RateLimitConfig,
  type RetryConfig,
  type RetryMiddlewareOptions,
} from '@astroid/core';
export {
  createRateLimiterMiddleware,
  rateLimiterMiddleware,
  type RateLimitMiddlewareOptions,
} from './middleware/rate-limiter.js';
export * from '@astroid/types';
export {
  AstroidError,
  AuthenticationError,
  AuthorizationError,
  ForbiddenError,
  ValidationError,
  NotFoundError,
  ConflictError,
  PolicyViolationError,
  BudgetExceededError,
  ApprovalRequiredError,
  RateLimitError,
  NetworkError,
  InternalServerError,
  ServerError,
  isAstroidError,
} from '@astroid/errors';
export {
  InsufficientFundsError,
  AstroidPolicyViolationError,
  AstroidInsufficientFundsError,
  AstroidApiError,
  AstroidValidationError,
  AstroidNetworkError,
} from '@astroid/errors';
// Centralized Stellar domain errors and mapping (issue #253).
export {
  InsufficientBalanceError,
  TrustlineMissingError,
  StellarAuthError,
  SequenceConflictError,
  TransactionExpiredError,
  StellarMalformedError,
  StellarNetworkError,
  mapStellarError,
  extractStellarResultCodes,
  errorClassForStellarCode,
  isStellarError,
} from '@astroid/errors';
export {
  createErrorTranslatorMiddleware,
  errorTranslatorMiddleware,
  errorMiddleware,
  translateErrorBody,
} from './middleware/error.js';
export {
  createCorrelationMiddleware,
  correlationMiddleware,
  CORRELATION_ID_HEADER,
  REQUEST_ID_HEADER,
  X_CORRELATION_ID_HEADER,
  type CorrelationTracingConfig,
} from './middleware/correlation.js';

// Re-export telemetry types for consumers
export {
  type TelemetryHooks,
  type TelemetryRequestInfo,
  type TelemetryResponseInfo,
} from '@astroid/core';

// Error response parser — re-exports so consumers can parse raw responses
// without reaching into internal modules.
export {
  StellarHorizonError,
  parseErrorResponse,
  parseErrorBody,
  type ParsedError,
} from './errors.js';
export { createErrorParserMiddleware } from './error-parser-middleware.js';

// Token refresh interceptor — single-flight refresh + request queueing.
export {
  createTokenRefreshInterceptor,
  type TokenRefreshInterceptor,
  type TokenRefreshInterceptorOptions,
  type UnauthorizedHandler,
} from './token-refresh.js';

// Shared auto-pagination helpers — cursor (keyset) iteration for any list endpoint.
export {
  paginateCursor,
  normalizeCursorPage,
  MAX_CURSOR_PAGES,
  type CursorPage,
  type CursorPageFetcher,
  type PaginateCursorOptions,
} from './pagination.js';
