import type { Context, Env, MiddlewareHandler } from "hono";
import type {
  AuthCredentials,
  OAuth2FlowTokenResponse,
  StrategyError,
  StrategyOptions,
  StrategyResult,
  StrategyVerifyTokenFunction,
} from "@saurbit/oauth2";

/**
 * Hono `Env` extension that injects OAuth2 credentials into the context variable map.
 *
 * Merge this into your application `Env` type so that `c.get("credentials")`
 * is typed as {@link AuthCredentials} after a successful token verification.
 *
 * @example
 * ```ts
 * type AppEnv = OAuth2ServerEnv & { Bindings: { DB: D1Database } };
 * ```
 */
export interface OAuth2ServerEnv extends Env {
  Variables: {
    /** The verified token credentials set by `authorizeMiddleware` for downstream handlers. */
    credentials?: AuthCredentials;
  };
}

/**
 * Hono-adapted variant of `StrategyOptions`.
 *
 * Replaces the base `verifyToken` signature so the handler receives a typed
 * Hono `Context` instead of a raw `Request`, giving access to variables,
 * environment bindings, and other Hono-specific state.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoStrategyOptions<E extends Env = Env>
  extends Omit<StrategyOptions, "verifyToken"> {
  /** Handler to verify an extracted access token. Receives the full Hono context. */
  verifyToken?: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>;
}

/**
 * Callback invoked when token verification or scope enforcement fails.
 *
 * Use this to customise the error response - for example, throwing an
 * `HTTPException`, redirecting the user, or logging the failure.
 * If not provided, the default behaviour is to throw an HTTP 401 exception.
 *
 * @template E - The Hono `Env` type for the application.
 *
 * @param context - The Hono context for the current request.
 * @param error - The strategy error that caused the authorization failure.
 */
export interface FailedAuthorizationAction<E extends Env = Env> {
  (context: Context<E & OAuth2ServerEnv>, error: StrategyError): Promise<void> | void;
}

/**
 * Strategy options passed to Hono OAuth2 flow builders.
 *
 * Combines token verification and the failed-authorization callback into a
 * single options object consumed by all Hono flow classes.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoOAuth2StrategyOptions<E extends Env = Env>
  extends Omit<HonoStrategyOptions<E>, "tokenType"> {
  /**
   * Action to invoke when token verification or scope enforcement fails.
   * Defaults to throwing an HTTP 401 exception when not provided.
   */
  failedAuthorizationAction?: FailedAuthorizationAction<E>;
}

/**
 * Core Hono-adapted methods shared by all OAuth2 flow adapters.
 *
 * Obtained via the `.hono()` method on any flow class (e.g.
 * `flow.hono().authorizeMiddleware(["scope"])`). All methods accept a Hono
 * `Context` rather than a raw `Request`.
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoMethods<E extends Env = Env> {
  /**
   * Returns a Hono middleware that verifies the bearer token on incoming requests
   * and optionally enforces the given scopes.
   *
   * On success, sets `c.get("credentials")` for downstream handlers.
   * On failure, invokes the configured {@link FailedAuthorizationAction}.
   *
   * @param scopes - Optional list of scopes that the token must include.
   */
  authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv>;
  /**
   * Handles a token endpoint request and returns a typed token response.
   *
   * @param context - The Hono context for the token endpoint request.
   */
  token(context: Context): Promise<OAuth2FlowTokenResponse>;
  /**
   * Extracts and verifies the bearer token from the request.
   *
   * @param context - The Hono context for the current request.
   * @returns A {@link StrategyResult} indicating success or failure.
   */
  verifyToken(context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult>;
}

/**
 * Marker interface implemented by all Hono-adapted OAuth2 flow classes.
 *
 * Guarantees that the class exposes a `.hono()` accessor returning the
 * Hono-specific method surface ({@link HonoMethods}).
 *
 * @template E - The Hono `Env` type for the application.
 */
export interface HonoAdapted<E extends Env = Env> {
  /**
   * Returns the Hono-adapted method surface for this flow.
   *
   * The returned object is frozen; use its methods directly inside Hono route handlers.
   */
  hono(): HonoMethods<E>;
}
