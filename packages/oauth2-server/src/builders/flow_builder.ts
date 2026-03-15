import { ClientSecretBasic } from "../client_auth_methods/client_secret_basic.ts";
import { ClientSecretPost } from "../client_auth_methods/client_secret_post.ts";
import { NoneAuthMethod } from "../client_auth_methods/none.ts";
import { ClientAuthMethod, TokenEndpointAuthMethod } from "../client_auth_methods/types.ts";
import { OAuth2Flow, OAuth2FlowOptions } from "../grants/flow.ts";
import { StrategyVerifyTokenFunction } from "../strategy.ts";
import { TokenType } from "../token_types/types.ts";

export abstract class OAuth2FlowBuilder {
  protected params: OAuth2FlowOptions;
  protected clientAuthenticationMethods: Map<TokenEndpointAuthMethod, ClientAuthMethod> = new Map();

  constructor(params: Partial<OAuth2FlowOptions>) {
    const { clientAuthenticationMethods, ...options } = params;
    this.params = {
      strategyOptions: options.strategyOptions || {},
      ...options,
    };

    if (clientAuthenticationMethods) {
      for (const method of clientAuthenticationMethods) {
        this.addClientAuthenticationMethod(method);
      }
    }
  }

  getAccessTokenLifetime(): number | undefined {
    return this.params.accessTokenLifetime;
  }

  getSecuritySchemeName(): string | undefined {
    return this.params.securitySchemeName;
  }

  getTokenEndpoint(): string | undefined {
    return this.params.tokenEndpoint;
  }

  getDescription(): string | undefined {
    return this.params.description;
  }

  getScopes(): Record<string, string> {
    return { ...this.params.scopes || {} };
  }

  setAccessTokenLifetime(lifetime: number): this {
    this.params.accessTokenLifetime = lifetime;
    return this;
  }

  setSecuritySchemeName(name: string): this {
    this.params.securitySchemeName = name;
    return this;
  }

  setTokenEndpoint(url: string): this {
    this.params.tokenEndpoint = url;
    return this;
  }

  setTokenType(tokenType: TokenType): this {
    this.params.tokenType = tokenType;
    return this;
  }

  setDescription(description: string): this {
    this.params.description = description;
    return this;
  }

  setScopes(scopes: Record<string, string>): this {
    this.params.scopes = scopes;
    return this;
  }

  verifyToken(handler: StrategyVerifyTokenFunction<Request>): this {
    this.params.strategyOptions.verifyToken = handler;
    return this;
  }

  addClientAuthenticationMethod(
    value: "client_secret_basic" | "client_secret_post" | "none" | ClientAuthMethod,
  ): this {
    if (value == "client_secret_basic") {
      this.clientSecretBasicAuthenticationMethod();
    } else if (value == "client_secret_post") {
      this.clientSecretPostAuthenticationMethod();
    } else if (value == "none") {
      this.noneAuthenticationMethod();
    } else {
      this.clientAuthenticationMethods.set(value.method, value);
    }
    return this;
  }

  removeClientAuthenticationMethod(
    method: TokenEndpointAuthMethod,
  ): this {
    this.clientAuthenticationMethods.delete(method);
    return this;
  }

  clientSecretBasicAuthenticationMethod(): this {
    const clientAuthenticationMethod = new ClientSecretBasic();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  clientSecretPostAuthenticationMethod(): this {
    const clientAuthenticationMethod = new ClientSecretPost();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  noneAuthenticationMethod(): this {
    const clientAuthenticationMethod = new NoneAuthMethod();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  protected buildParams(): OAuth2FlowOptions {
    const params: OAuth2FlowOptions = { ...this.params };

    if (this.clientAuthenticationMethods.size > 0) {
      params.clientAuthenticationMethods = Array.from(
        this.clientAuthenticationMethods.values(),
      );
    }
    return params;
  }

  abstract build(): OAuth2Flow;
}
