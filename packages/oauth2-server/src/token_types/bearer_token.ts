import type { TokenType, TokenValidationResponse } from "./types.ts";

export type BearerTokenValidation = (
  request: Request,
  token: string
) => TokenValidationResponse | Promise<TokenValidationResponse>;

export class BearerToken implements TokenType {
  readonly prefix = "Bearer" as const;
  #handler: BearerTokenValidation;

  constructor() {
    this.#handler = (_, token) => ({ isValid: !!token });
  }

  validate(handler: BearerTokenValidation): this {
    this.#handler = handler;
    return this;
  }

  isValid(request: Request, token: string): Promise<TokenValidationResponse> | TokenValidationResponse {
    return this.#handler(request, token);
  }
}