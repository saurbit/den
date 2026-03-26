/**
 * @module
 *
 * Implements the `none` client authentication method, used by public clients
 * (e.g. native apps, SPAs) that have no client secret and authenticate solely
 * by including their `client_id` in the request body.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
 * @see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
 */

import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

/**
 * {@link ClientAuthMethod} implementation for the `none` authentication method.
 *
 * Used by public clients that cannot securely hold a client secret. Only a
 * `client_id` is extracted from the request body - no secret is required or expected.
 *
 * Typically used alongside PKCE in the Authorization Code flow.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7636
 */
export class NoneAuthMethod implements ClientAuthMethod {
  /**
   * The identifier for this authentication method.
   * Always `"none"`.
   */
  get method(): "none" {
    return "none";
  }

  /**
   * Whether the client secret is optional for this method.
   * Always `true` - public clients using `none` have no client secret.
   */
  get secretIsOptional(): boolean {
    return true;
  }

  /**
   * Extracts the `client_id` from the request body.
   *
   * Sets `hasAuthMethod` to `true` only when a `client_id` field is present in the body.
   * No `client_secret` is extracted or expected.
   *
   * Supports `application/x-www-form-urlencoded` and `application/json` content types.
   * Returns `{ hasAuthMethod: false }` for any other content type.
   *
   * @param req - The incoming HTTP request.
   * @returns The extracted `client_id`, or `{ hasAuthMethod: false }` if no
   *   `client_id` field is found in the body.
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
      };
    } else if (contentType.includes("application/json")) {
      body = req.json ? await req.json() : null;
    } else {
      body = null;
    }

    if (
      body && typeof body === "object" && "client_id" in body && typeof body.client_id === "string"
    ) {
      res.hasAuthMethod = true;
      if (typeof body.client_id === "string") res.clientId = body.client_id;
    }

    return res;
  }
}
