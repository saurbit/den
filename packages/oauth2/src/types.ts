/**
 * Represents the response body returned by the token endpoint.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
 */
export interface OAuth2TokenResponseBody {
  /** The access token issued by the authorization server. */
  access_token: string;

  /** The type of token issued (e.g., `"Bearer"`, `"DPoP"`). */
  token_type: string;

  /** The lifetime in seconds of the access token. */
  expires_in?: number;

  /** The refresh token, which can be used to obtain new access tokens. */
  refresh_token?: string;

  /** The scope of the access token, as a space-delimited list. */
  scope?: string;

  /** The ID token, issued when the OpenID Connect scope is requested. */
  id_token?: string;

  /**
   * Ensures this type is not used in error response positions.
   * @internal
   */
  error?: never;

  /** Additional properties returned by the token endpoint. */
  [key: string]: unknown;
}

/**
 * Represents a registered OAuth 2.0 client.
 */
export interface OAuth2Client {
  /** Unique client identifier. */
  id: string;

  /** Client secret (for confidential clients). */
  secret?: string;

  /** Allowed redirect URIs. */
  redirectUris: string[];

  /** Grant types the client is authorized to use. */
  grants: string[];

  /** Scopes the client is allowed to request. */
  scopes?: string[];

  /** Additional client metadata. */
  metadata?: Record<string, unknown>;
}
