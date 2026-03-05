import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  type AuthCredentials,
  ClientCredentialsGrantFlow,
  ClientCredentialsGrantFlowOptions,
  evaluateStrategy,
  OAuth2AuthFlowTokenResponse,
  StrategyError,
  StrategyInsufficientScopeError,
  StrategyInternalError,
  type StrategyOptions,
  StrategyResult,
  StrategyVerifyTokenFunction,
} from "@saurbit/oauth2-server";

export interface OAuth2ServerEnv extends Env {
  Variables: {
    credentials?: AuthCredentials;
  };
}

export interface HonoStrategyOptions<E extends Env = Env>
  extends Omit<StrategyOptions, "verifyToken"> {
  verifyToken?: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>;
}

// Re-export for convenience
export type {
  AuthCredentials,
  StrategyOptions,
  StrategyVerifyTokenFunction,
  TokenType,
  TokenTypeValidationResponse,
} from "@saurbit/oauth2-server";
export { BearerTokenType } from "@saurbit/oauth2-server";

/**
 * Hono adapter for the oauth2-server strategy.
 */
export function createAuthMiddleware<E extends Env = Env>(
  options: HonoStrategyOptions<E>,
): MiddlewareHandler<E & OAuth2ServerEnv> {
  return async (c, next) => {
    const honoVerifyToken = options.verifyToken;
    const verifyToken: StrategyVerifyTokenFunction | undefined = honoVerifyToken
      ? async (_, params) => {
        return await honoVerifyToken(c, params);
      }
      : undefined;

    const result = await evaluateStrategy(c.req.raw, {
      ...options,
      verifyToken,
    });

    if (result.success) {
      // set credentials in context for downstream handlers
      c.set("credentials", result.credentials);
      return await next();
    }

    let message: string;
    if (Deno.env.get("DENO_ENV") === "production") {
      message = result.error instanceof StrategyInternalError
        ? "Internal Server Error"
        : "Unauthorized";
    } else {
      message = result.error.message;
    }

    throw new HTTPException(result.error.status, {
      message,
    });
  };
}

export interface FailedAuthorizationAction<E extends Env = Env> {
  (context: Context<E & OAuth2ServerEnv>, error: StrategyError): Promise<void> | void;
}

export interface HonoStrategyOptionsWithFailedAuth<E extends Env = Env>
  extends Omit<HonoStrategyOptions<E>, "tokenType"> {
  failedAuthorizationAction?: FailedAuthorizationAction<E>;
}

export interface HonoClientCredentialsFlowOptions<E extends Env = Env>
  extends Omit<ClientCredentialsGrantFlowOptions, "strategyOptions"> {
  strategyOptions: HonoStrategyOptionsWithFailedAuth<E>;
}

export class HonoClientCredentialsGrantFlow<
  E extends Env = Env,
> extends ClientCredentialsGrantFlow {
  readonly #authorizeHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  constructor(options: HonoClientCredentialsFlowOptions<E>) {
    const { strategyOptions, ...flowOptions } = options;

    super({
      ...flowOptions,
      strategyOptions: {},
    });

    this.#failedAuthorizationAction = strategyOptions.failedAuthorizationAction ?? (() => {
      throw new HTTPException(401, {
        message: "Unauthorized",
      });
    });

    this.#authorizeHandler = async (context: Context<E & OAuth2ServerEnv>) => {
      const honoVerifyToken = strategyOptions.verifyToken;
      const verifyToken: StrategyVerifyTokenFunction | undefined = honoVerifyToken
        ? async (_, params) => {
          return await honoVerifyToken(context, params);
        }
        : undefined;

      return await evaluateStrategy(context.req.raw, {
        ...strategyOptions,
        verifyToken,
        tokenType: this._tokenType,
      });
    };

    this.#authorizeMiddleware = this.#createAuthorizeMiddleware([]);
  }

  #createAuthorizeMiddleware(scopes: string[]): MiddlewareHandler<E & OAuth2ServerEnv> {
    return async (c, next) => {
      const result = await this.verifyTokenFromHono(c);

      if (result.success) {
        if (
          scopes.length &&
          !scopes.every((n) => result.credentials?.scope?.includes(n))
        ) {
          return this.#failedAuthorizationAction(
            c,
            new StrategyInsufficientScopeError("Insufficient scope"),
          );
        }
        // set credentials in context for downstream handlers
        c.set("credentials", result.credentials);
        return await next();
      }
      return this.#failedAuthorizationAction(c, result.error);
    };
  }

  async verifyTokenFromHono(
    context: Context<E & OAuth2ServerEnv>,
  ): Promise<StrategyResult> {
    return await this.#authorizeHandler(context);
  }

  async tokenFromHono(context: Context): Promise<OAuth2AuthFlowTokenResponse> {
    return await this.token(context.req.raw);
  }

  authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> {
    return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
  }
}
