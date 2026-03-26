import type { TokenType, TokenTypeValidationResponse } from "./types.ts";

/**
 * A custom handler for validating a Bearer token on a protected resource endpoint.
 *
 * @param request - The incoming HTTP request.
 * @param token - The raw Bearer token extracted from the `Authorization` header.
 * @returns A validation response indicating whether the token is valid.
 */
export type BearerTokenValidation = (
  request: Request,
  token: string,
) => TokenTypeValidationResponse | Promise<TokenTypeValidationResponse>;

/**
 * {@link TokenType} implementation for the Bearer token scheme.
 *
 * By default, considers any non-empty token string valid. Use {@link BearerTokenType.validate}
 * to supply a custom validation handler (e.g. JWT signature verification, database lookup).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc6750
 */
export class BearerTokenType implements TokenType {
  /**
   * The token type prefix used in the `Authorization` header and `token_type` response field.
   * Always `"Bearer"`.
   */
  readonly prefix = "Bearer" as const;

  #handler: BearerTokenValidation;

  constructor() {
    this.#handler = (_, token) => ({ isValid: !!token });
  }

  /**
   * Overrides the default Bearer token validation handler.
   *
   * @param handler - A custom {@link BearerTokenValidation} function.
   */
  validate(handler: BearerTokenValidation): this {
    this.#handler = handler;
    return this;
  }

  /**
   * Validates the Bearer token extracted from an incoming request.
   *
   * @param request - The incoming HTTP request.
   * @param token - The raw Bearer token extracted from the `Authorization` header.
   * @returns A validation response indicating whether the token is valid.
   */
  isValid(
    request: Request,
    token: string,
  ): Promise<TokenTypeValidationResponse> | TokenTypeValidationResponse {
    return this.#handler(request, token);
  }
}
