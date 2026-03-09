import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  ClientCredentialsFlow,
  ClientCredentialsFlowOptions,
  evaluateStrategy,
  OAuth2FlowTokenResponse,
  StrategyInsufficientScopeError,
  StrategyResult,
  StrategyVerifyTokenFunction,
} from "@saurbit/oauth2-server";
import {
  FailedAuthorizationAction,
  HonoStrategyOptionsWithFailedAuth,
  OAuth2ServerEnv,
} from "./types.ts";

export interface HonoClientCredentialsFlowOptions<E extends Env = Env>
  extends Omit<ClientCredentialsFlowOptions, "strategyOptions"> {
  strategyOptions: HonoStrategyOptionsWithFailedAuth<E>;
}

export class HonoClientCredentialsFlow<
  E extends Env = Env,
> extends ClientCredentialsFlow {
  readonly #verifyTokenHandler: (
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

    this.#verifyTokenHandler = async (context: Context<E & OAuth2ServerEnv>) => {
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
    return await this.#verifyTokenHandler(context);
  }

  async tokenFromHono(context: Context): Promise<OAuth2FlowTokenResponse> {
    return await this.token(context.req.raw);
  }

  authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> {
    return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
  }
}
