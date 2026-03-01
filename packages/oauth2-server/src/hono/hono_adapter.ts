import type { MiddlewareHandler, Env, Context } from "hono";
import { HTTPException } from "hono/http-exception";
import { evaluateStrategy, type StrategyOptions, type AuthCredentials } from "../strategy.ts";

export interface Oauth2ServerEnv extends Env {
  Variables: {
    credentials?: AuthCredentials;
  };
}

// Re-export for convenience
export type { StrategyOptions, AuthCredentials, TokenType, TokenValidationResponse } from "../strategy.ts";
export { BearerToken } from "../bearer_token.ts";

/**
 * Hono adapter for the oauth2-server strategy.
 */
export function integrateStrategy<E extends Env = Env>(
  options: StrategyOptions
): MiddlewareHandler<E & Oauth2ServerEnv> {
  return async (c, next) => {
    const result = await evaluateStrategy(c.req.raw, options);

    if (result.success) {
      c.set("credentials", result.credentials);
      return await next();
    }

    throw new HTTPException(result.status, { message: result.message });
  };
}