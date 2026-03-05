import type { Context, Env } from "hono";
import {
  type AuthCredentials,
  StrategyError,
  type StrategyOptions,
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

export interface FailedAuthorizationAction<E extends Env = Env> {
  (context: Context<E & OAuth2ServerEnv>, error: StrategyError): Promise<void> | void;
}

export interface HonoStrategyOptionsWithFailedAuth<E extends Env = Env>
  extends Omit<HonoStrategyOptions<E>, "tokenType"> {
  failedAuthorizationAction?: FailedAuthorizationAction<E>;
}
