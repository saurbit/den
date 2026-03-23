// oauth2_hono_adapter/authorization_code.ts

import type { Context, Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  DeviceAuthorizationEndpointResponse,
  DeviceAuthorizationProcessResponse,
  evaluateStrategy,
  InvalidRequestError,
  OAuth2FlowTokenResponse,
  StrategyInsufficientScopeError,
  StrategyResult,
  StrategyVerifyTokenFunction,
} from "@saurbit/oauth2";
import {
  FailedAuthorizationAction,
  HonoAdapted,
  HonoOAuth2StrategyOptions,
  OAuth2ServerEnv,
} from "./types.ts";
import { OIDCDeviceAuthorizationFlowOptions } from "@saurbit/oauth2";
import { OIDCDeviceAuthorizationFlowBuilder } from "@saurbit/oauth2";
import { OIDCDeviceAuthorizationFlow } from "@saurbit/oauth2";
import { HonoDeviceAuthorizationMethods } from "./device_authorization.ts";

//#region Types and Interfaces

export interface HonoOIDCDeviceAuthorizationFlowOptions<
  E extends Env = Env,
> extends Omit<OIDCDeviceAuthorizationFlowOptions, "strategyOptions"> {
  strategyOptions: HonoOAuth2StrategyOptions<E>;
}

export interface HonoOIDCDeviceAuthorizationFlowBuilderOptions<
  E extends Env = Env,
> extends Partial<HonoOIDCDeviceAuthorizationFlowOptions<E>> {
}

//#endregion

//#region Classes

export class HonoOIDCDeviceAuthorizationFlow<
  E extends Env = Env,
> extends OIDCDeviceAuthorizationFlow implements HonoAdapted<E> {
  readonly #verifyTokenHandler: (
    context: Context<E & OAuth2ServerEnv>,
  ) => Promise<StrategyResult>;
  readonly #authorizeMiddleware: MiddlewareHandler<E & OAuth2ServerEnv>;

  readonly #failedAuthorizationAction: FailedAuthorizationAction<E>;

  readonly #hono: HonoDeviceAuthorizationMethods<E> = {
    authorizeMiddleware: (scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> => {
      return scopes?.length ? this.#createAuthorizeMiddleware(scopes) : this.#authorizeMiddleware;
    },
    token: async (context: Context): Promise<OAuth2FlowTokenResponse> => {
      return await this.token(context.req.raw);
    },

    verifyToken: async (context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> => {
      return await this.#verifyTokenHandler(context);
    },

    processAuthorization: async (
      context: Context,
    ): Promise<DeviceAuthorizationProcessResponse> => {
      return await this.processAuthorization(
        context.req.raw.clone(),
      );
    },

    handleAuthorizationEndpoint: async (
      context: Context,
    ): Promise<DeviceAuthorizationEndpointResponse> => {
      if (context.req.method === "POST") {
        // In a real implementation, you would authenticate the user here,
        // and if authentication is successful, generate an authorization code,
        // and redirect the user to the redirect_uri with the code and state as query parameters.

        const result = await this.hono().processAuthorization(context);

        if (result.type === "error") {
          return result;
        }

        return {
          ...result,
          method: "POST",
        };
      }

      return {
        type: "error",
        error: new InvalidRequestError("Unsupported HTTP method"),
      };
    },
  };

  constructor(options: HonoOIDCDeviceAuthorizationFlowOptions<E>) {
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
      const result = await this.hono().verifyToken(c);

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

  hono(): Readonly<HonoDeviceAuthorizationMethods<E>> {
    return Object.freeze(this.#hono);
  }
}

//#endregion

//#region Builders

export class HonoOIDCDeviceAuthorizationFlowBuilder<
  E extends Env = Env,
> extends OIDCDeviceAuthorizationFlowBuilder {
  protected strategyOptions: HonoOAuth2StrategyOptions<E> = {};

  constructor(options?: HonoOIDCDeviceAuthorizationFlowBuilderOptions<E>) {
    const { strategyOptions, ...flowOptions } = options || {};
    super({
      ...flowOptions,
      strategyOptions: {},
    });
    this.strategyOptions = strategyOptions || {};
  }

  static create<
    E extends Env = Env,
  >(
    options?: HonoOIDCDeviceAuthorizationFlowBuilderOptions<E>,
  ) {
    return new HonoOIDCDeviceAuthorizationFlowBuilder<E>(options);
  }

  failedAuthorizationAction(action: FailedAuthorizationAction<E>): this {
    this.strategyOptions.failedAuthorizationAction = action;
    return this;
  }

  /**
   * This method is overridden to prevent setting a verifyToken handler that does not have access to the Hono context.
   * Use `verifyTokenHandler` instead to set a handler that receives the Hono context.
   * @deprecated Use `verifyTokenHandler` instead to set a handler that receives the Hono context.
   * @param _handler
   * @returns
   */
  override verifyToken(_handler: StrategyVerifyTokenFunction<Request>): this {
    throw new Error("Use verifyTokenHandler() instead, which provides access to the Hono context.");
  }

  verifyTokenHandler(handler: StrategyVerifyTokenFunction<Context<E & OAuth2ServerEnv>>): this {
    this.strategyOptions.verifyToken = handler;
    return this;
  }

  override build(): HonoOIDCDeviceAuthorizationFlow<E> {
    const params: HonoOIDCDeviceAuthorizationFlowOptions<E> = {
      ...this.buildParams(),
      strategyOptions: this.strategyOptions,
    };
    return new HonoOIDCDeviceAuthorizationFlow<E>(params);
  }
}

//#endregion
