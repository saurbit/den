/**
 * @module flow_builder
 * @description Abstract base builder for all OAuth2 flow builders.
 * Provides chainable setter methods for the common configuration shared across every
 * grant type: token endpoint, scopes, access token lifetime, security scheme name,
 * token type, description, and client authentication methods.
 */

import { ClientSecretBasic } from "../client_auth_methods/client_secret_basic.ts";
import { ClientSecretPost } from "../client_auth_methods/client_secret_post.ts";
import { NoneAuthMethod } from "../client_auth_methods/none.ts";
import { ClientAuthMethod, TokenEndpointAuthMethod } from "../client_auth_methods/types.ts";
import { OAuth2Flow, OAuth2FlowOptions } from "../grants/flow.ts";
import { StrategyVerifyTokenFunction } from "../strategy.ts";
import { TokenType } from "../token_types/types.ts";

/**
 * Abstract base class for all OAuth2 flow builders.
 *
 * Subclasses extend this with grant-specific model callbacks and produce a concrete
 * {@link OAuth2Flow} instance via {@link build}. All setter methods return `this`
 * to support fluent chaining.
 *
 * @example
 * ```ts
 * // Typically used via a concrete subclass:
 * const flow = new ClientCredentialsFlowBuilder({ tokenEndpoint: "/token" })
 *   .setScopes({ "read:data": "Read access to data" })
 *   .clientSecretBasicAuthenticationMethod()
 *   .generateAccessToken(async (ctx) => ({ accessToken: issueToken(ctx) }))
 *   .build();
 * ```
 */
export abstract class OAuth2FlowBuilder {
  protected params: OAuth2FlowOptions;
  protected clientAuthenticationMethods: Map<TokenEndpointAuthMethod, ClientAuthMethod> = new Map();

  /**
   * Creates a new `OAuth2FlowBuilder` with the given partial options.
   * Any `clientAuthenticationMethods` supplied in `params` are registered immediately
   * via {@link addClientAuthenticationMethod}.
   * @param params - Partial flow options used to seed the builder state.
   */
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

  /**
   * Returns the configured access token lifetime in seconds.
   * @returns The access token lifetime, or `undefined` if not set.
   */
  getAccessTokenLifetime(): number | undefined {
    return this.params.accessTokenLifetime;
  }

  /**
   * Returns the security scheme name used in OpenAPI documentation.
   * @returns The security scheme name, or `undefined` if not set.
   */
  getSecuritySchemeName(): string | undefined {
    return this.params.securitySchemeName;
  }

  /**
   * Returns the token endpoint URL.
   * @returns The token endpoint URL, or `undefined` if not set.
   */
  getTokenEndpoint(): string | undefined {
    return this.params.tokenEndpoint;
  }

  /**
   * Returns the human-readable description of this flow, used in OpenAPI documentation.
   * @returns The description string, or `undefined` if not set.
   */
  getDescription(): string | undefined {
    return this.params.description;
  }

  /**
   * Returns a copy of the configured scopes map.
   * @returns A shallow copy of the scopes record (scope name → description).
   */
  getScopes(): Record<string, string> {
    return { ...this.params.scopes || {} };
  }

  /**
   * Sets the access token lifetime in seconds.
   * @param lifetime - The number of seconds an issued access token remains valid.
   * @returns `this` for chaining.
   */
  setAccessTokenLifetime(lifetime: number): this {
    this.params.accessTokenLifetime = lifetime;
    return this;
  }

  /**
   * Sets the security scheme name used to identify this flow in OpenAPI documentation.
   * @param name - The security scheme name (e.g. `"OAuth2"`).
   * @returns `this` for chaining.
   */
  setSecuritySchemeName(name: string): this {
    this.params.securitySchemeName = name;
    return this;
  }

  /**
   * Sets the token endpoint URL where clients exchange credentials or codes for tokens.
   * @param url - The token endpoint URL (e.g. `/oauth/token`).
   * @returns `this` for chaining.
   */
  setTokenEndpoint(url: string): this {
    this.params.tokenEndpoint = url;
    return this;
  }

  /**
   * Sets the token type implementation used for access token validation.
   * Defaults to Bearer if not set.
   * @param tokenType - A {@link TokenType} instance (e.g. `BearerTokenType`, `DPoPTokenType`).
   * @returns `this` for chaining.
   */
  setTokenType(tokenType: TokenType): this {
    this.params.tokenType = tokenType;
    return this;
  }

  /**
   * Sets the human-readable description of this flow for use in OpenAPI documentation.
   * @param description - A description string.
   * @returns `this` for chaining.
   */
  setDescription(description: string): this {
    this.params.description = description;
    return this;
  }

  /**
   * Sets the scopes supported by this flow.
   * @param scopes - A record mapping scope names to their human-readable descriptions.
   * @returns `this` for chaining.
   */
  setScopes(scopes: Record<string, string>): this {
    this.params.scopes = scopes;
    return this;
  }

  /**
   * Sets a custom token verification handler used by the strategy middleware to
   * validate access tokens on protected routes.
   * @param handler - The token verification function.
   * @returns `this` for chaining.
   */
  verifyToken(handler: StrategyVerifyTokenFunction<Request>): this {
    this.params.strategyOptions.verifyToken = handler;
    return this;
  }

  /**
   * Registers a client authentication method by name or by providing a custom
   * {@link ClientAuthMethod} instance.
   * Passing the string `"client_secret_basic"`, `"client_secret_post"`, or `"none"`
   * is equivalent to calling the corresponding convenience method.
   * @param value - A well-known method name or a custom `ClientAuthMethod` instance.
   * @returns `this` for chaining.
   */
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

  /**
   * Removes a previously registered client authentication method by its method identifier.
   * @param method - The `TokenEndpointAuthMethod` identifier to remove.
   * @returns `this` for chaining.
   */
  removeClientAuthenticationMethod(
    method: TokenEndpointAuthMethod,
  ): this {
    this.clientAuthenticationMethods.delete(method);
    return this;
  }

  /**
   * Registers the `client_secret_basic` authentication method (HTTP Basic Auth).
   * Client ID and secret are expected in the `Authorization` header.
   * @returns `this` for chaining.
   */
  clientSecretBasicAuthenticationMethod(): this {
    const clientAuthenticationMethod = new ClientSecretBasic();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  /**
   * Registers the `client_secret_post` authentication method.
   * Client ID and secret are expected as `client_id` / `client_secret` fields in
   * the request body.
   * @returns `this` for chaining.
   */
  clientSecretPostAuthenticationMethod(): this {
    const clientAuthenticationMethod = new ClientSecretPost();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  /**
   * Registers the `none` authentication method for public clients that do not
   * authenticate (no client secret required).
   * @returns `this` for chaining.
   */
  noneAuthenticationMethod(): this {
    const clientAuthenticationMethod = new NoneAuthMethod();
    this.clientAuthenticationMethods.set(
      clientAuthenticationMethod.method,
      clientAuthenticationMethod,
    );
    return this;
  }

  /**
   * Assembles the complete {@link OAuth2FlowOptions} from the current builder state,
   * including any registered client authentication methods.
   * @returns The options object used to construct the flow.
   */
  protected buildParams(): OAuth2FlowOptions {
    const params: OAuth2FlowOptions = { ...this.params };

    if (this.clientAuthenticationMethods.size > 0) {
      params.clientAuthenticationMethods = Array.from(
        this.clientAuthenticationMethods.values(),
      );
    }
    return params;
  }

  /**
   * Constructs and returns a fully configured {@link OAuth2Flow} instance.
   * Must be implemented by each concrete subclass to return the appropriate flow type.
   * @returns A new `OAuth2Flow` ready for use in a route handler.
   */
  abstract build(): OAuth2Flow;
}
