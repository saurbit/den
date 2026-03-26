/**
 * @module
 *
 * Implements the `client_secret_post` client authentication method, where the
 * client authenticates by including its `client_id` and `client_secret` in the
 * request body as form-urlencoded or JSON parameters.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
 */

import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

/**
 * {@link ClientAuthMethod} implementation for the `client_secret_post` authentication method.
 *
 * Extracts client credentials from the request body (`client_id` and `client_secret`
 * parameters), supporting both `application/x-www-form-urlencoded` and `application/json`
 * content types.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1
 */
export class ClientSecretPost implements ClientAuthMethod {
  /**
   * The identifier for this authentication method.
   * Always `"client_secret_post"`.
   */
  get method(): "client_secret_post" {
    return "client_secret_post";
  }

  /**
   * Whether the client secret is optional for this method.
   * Always `false` - a client secret is required for `client_secret_post`.
   */
  get secretIsOptional(): boolean {
    return false;
  }

  /**
   * Extracts the `client_id` and `client_secret` from the request body.
   *
   * Sets `hasAuthMethod` to `true` only when both `client_id` and `client_secret`
   * fields are present in the body, allowing the caller to distinguish between
   * "this method was attempted" and "no credentials provided".
   *
   * Supports `application/x-www-form-urlencoded` and `application/json` content types.
   * Returns `{ hasAuthMethod: false }` for any other content type.
   *
   * @param req - The incoming HTTP request.
   * @returns The extracted client credentials, or `{ hasAuthMethod: false }` if the
   *   body does not contain `client_id` and `client_secret` fields.
   */
  async extractClientCredentials(req: Request): Promise<ClientAuthMethodResponse> {
    const res: ClientAuthMethodResponse = {
      hasAuthMethod: false,
    };

    // Extract info from the request body (either form-urlencoded or JSON)
    let body: unknown;
    const contentType = req.headers.get("content-type") || "";
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const form = await req.formData();
      body = {
        client_id: form.get("client_id"),
        client_secret: form.get("client_secret"),
      };
    } else if (contentType.includes("application/json")) {
      body = req.json ? await req.json() : null;
    } else {
      body = null;
    }

    if (
      body &&
      typeof body === "object" &&
      "client_id" in body &&
      "client_secret" in body
    ) {
      res.hasAuthMethod = true;
      if (typeof body.client_id === "string") res.clientId = body.client_id;
      if (typeof body.client_secret === "string") res.clientSecret = body.client_secret;
    }

    return res;
  }
}
