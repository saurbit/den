import { HonoOIDCMultipleFlows } from "@saurbit/hono-oauth2";
import { oidcAuthorizationCodeFlow } from "./oidc_authorization_code.ts";

const ISSUER = "http://localhost:3000";

export const oidcMultipleFlows = new HonoOIDCMultipleFlows({
  flows: [oidcAuthorizationCodeFlow],
  discoveryUrl: `${ISSUER}/.well-known/openid-configuration`,
  securitySchemeName: "honoOIDCMultipleFlows",
  description: "Multiple OIDC Flows for Hono API",
  jwksEndpoint: "/jwks",
  tokenEndpoint: "/token",
});
