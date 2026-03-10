import {
  OAuth2FlowTokenResponse,
  OIDCFlow,
  OIDCMultipleFlows,
  StrategyResult,
} from "@saurbit/oauth2-server";
import type { Context, Env, MiddlewareHandler } from "hono";
import { OAuth2ServerEnv } from "./types.ts";
import { HTTPException } from "hono/http-exception";

export interface HonoOIDCFlow<
  E extends Env = Env,
> extends OIDCFlow {
  authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv>;
  tokenFromHono(context: Context): Promise<OAuth2FlowTokenResponse>;
  verifyTokenFromHono(context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult>;
}

export class HonoOIDCMultipleFlows<
  E extends Env = Env,
> extends OIDCMultipleFlows<HonoOIDCFlow<E>> {
  async tokenFromHono(context: Context): Promise<OAuth2FlowTokenResponse> {
    return await this.tokenFromHono(context);
  }
  async verifyTokenFromHono(context: Context<E & OAuth2ServerEnv>): Promise<StrategyResult> {
    return await this.verifyTokenFromHono(context);
  }

  authorizeMiddleware(scopes?: string[]): MiddlewareHandler<E & OAuth2ServerEnv> {
    const middlewares = this.flows.map((flow) => flow.authorizeMiddleware(scopes));
    return async (context, next) => {
      for (const [i, middleware] of middlewares.entries()) {
        try {
          const response = await middleware(context, next);
          return response;
        } catch (error) {
          if (
            middlewares.length - 1 === i &&
            !(error instanceof HTTPException && error.status === 401)
          ) {
            throw error;
          }
        }
      }
    };
  }
}
