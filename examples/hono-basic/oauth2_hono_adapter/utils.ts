import type { Env, MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import {
  evaluateStrategy,
  StrategyInternalError,
  StrategyVerifyTokenFunction,
} from "@saurbit/oauth2-server";
import { HonoStrategyOptions, OAuth2ServerEnv } from "./types.ts";

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

    const message: string = result.error instanceof StrategyInternalError
      ? "Internal Server Error"
      : "Unauthorized";

    throw new HTTPException(result.error.status, {
      message,
    });
  };
}
