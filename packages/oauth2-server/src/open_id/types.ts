import { OAuth2Error } from "../errors.ts";
import { OAuth2TokenResponseBody } from "../types.ts";

export interface OpenIDTokenResponseBody extends OAuth2TokenResponseBody {
  id_token: string;
}

export type OpenIDFlowTokenResponse =
  | { success: true; tokenResponse: OpenIDTokenResponseBody }
  | { success: false; error: OAuth2Error };
