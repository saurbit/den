export interface OAuth2TokenResponseBody {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  error?: never;
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

/**
 * Represents an issued OAuth 2.0 access / refresh token pair.
 */
export interface OAuth2Token {
  /** The access token string. */
  accessToken: string;

  /** When the access token expires. */
  accessTokenExpiresAt: Date;

  /** The refresh token string (if issued). */
  refreshToken?: string;

  /** When the refresh token expires. */
  refreshTokenExpiresAt?: Date;

  /** The scopes granted to this token. */
  scope?: string[];

  /** The client this token was issued to. */
  client: OAuth2Client;

  /** The resource owner (user) this token represents. */
  user: Record<string, unknown>;
}
