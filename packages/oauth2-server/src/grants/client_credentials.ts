import { ClientSecretBasic } from "../client_auth_methods/client_secret_basic.ts";
import type { OAuth2Model } from "../types.ts";

/**
 * Handles the Client Credentials grant type.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.4
 */
export interface ClientCredentialsGrant {
  /** The grant type identifier. */
  readonly grantType: "client_credentials";
}

/**
 * @internal
 */
export class ClientCredentialsGrantImpl implements ClientCredentialsGrant {
  readonly grantType = "client_credentials" as const;
  readonly #model: OAuth2Model;

  constructor(model: OAuth2Model) {
    this.#model = model;
  }

  // TODO: implement client credentials exchange

  async token(request: Request): Promise<Response> {
    

    // Validate client authentication
    // TODO: support multiple client authentication methods, not just client_secret_basic
    const clientAuthMethod = new ClientSecretBasic();
    const { clientId, clientSecret, hasAuthMethod } = clientAuthMethod.extractClientCredentials(request);
    
    // If the request contains client authentication credentials, validate them
    if (hasAuthMethod) {

      // If clientId or clientSecret is missing, return 401 error
      if (!clientId || !clientSecret) {
        return new Response("Invalid client credentials", { status: 401 });
      }

      // Validate client credentials using the model's getClient() method
      // TODO: also send the grant type to getClient() so 
      // that model can validate that client is allowed to use this grant type
      const client = await this.#model.getClient(clientId, clientSecret);

      // If client authentication fails, return 401 error
      if (!client) {
        return new Response("Invalid client credentials", { status: 401 });
      }

      // validate that client is allowed to use client credentials grant type
      if (!client.grants || !client.grants.includes(this.grantType)) {
        return new Response("Unauthorized client for this grant type", { status: 401 });
      }

      // Validate scope if provided in the request body (optional)
      if (request.method === "POST") {
        const contentType = request.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
          const body: unknown = request.json ? await request.json() : null;
          if (body && typeof body === 'object' && 'scope' in body) {
            const requestedScopes = typeof body.scope === 'string' ? body.scope.split(' ') : [];
            const allowedScopes = client.scopes ? client.scopes : [];
            const validScopes = requestedScopes.filter(scope => allowedScopes.includes(scope));
            const invalidScopes = requestedScopes.filter(scope => !allowedScopes.includes(scope));
            if (invalidScopes.length > 0 && validScopes.length === 0) {
              return new Response("Invalid scope: " + invalidScopes.join(', '), { status: 400 });
            }
          }
        }
      }

      // TODO: also validate client metadata such as redirect URIs, if applicable for client credentials grant

      // TODO: generate access token and refresh token from client, valid scope, and any other relevant information, using the model's generateAccessToken() and generateRefreshToken() methods
      
      // TODO: generate access token, refresh token if applicable, and return response according to spec
      // return new Response(JSON.stringify({
      //   access_token: "generated_access_token",
      //   refresh_token: "generated_refresh_token_if_applicable",
      //   token_type: "Bearer",
      //   expires_in: 3600,
      //   scope: "requested scopes that were granted"
      // }), {
      //   status: 200,
      //   headers: {
      //     "Content-Type": "application/json"
      //   }
      // });
    }

    return new Response("Not implemented", { status: 501 });
  }
}
