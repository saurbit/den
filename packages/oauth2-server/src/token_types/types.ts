export type TokenValidationResponse = {
  isValid?: boolean;
  message?: string;
};

export interface TokenType {
  readonly prefix: string;
  isValid: (request: Request, token: string) => TokenValidationResponse | Promise<TokenValidationResponse>;
}