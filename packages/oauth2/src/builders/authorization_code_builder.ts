/**
 * @module authorization_code_builder
 * @description Fluent builder for constructing {@link AuthorizationCodeFlow} instances.
 * Provides setter methods for every model callback required by the Authorization Code grant,
 * including PKCE support, authorization endpoint configuration, and refresh token handling.
 */

import {
  AuthorizationCodeAccessTokenResult,
  AuthorizationCodeEndpointContext,
  AuthorizationCodeEndpointRequest,
  AuthorizationCodeFlow,
  AuthorizationCodeFlowOptions,
  AuthorizationCodeGrantContext,
  AuthorizationCodeModel,
  AuthorizationCodeReqData,
  AuthorizationCodeTokenRequest,
  GenerateAuthorizationCodeFunction,
  GetUserForAuthenticationFunction,
} from "../grants/authorization_code.ts";
import {
  OAuth2GenerateAccessTokenFromRefreshTokenFunction,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
  OAuth2RefreshTokenRequest,
} from "../grants/flow.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

/**
 * Fluent builder for {@link AuthorizationCodeFlow}.
 *
 * Collects all required model callbacks and configuration options through chainable
 * setter methods, then produces a fully configured `AuthorizationCodeFlow` instance
 * via {@link build}.
 *
 * @template AuthReqData - The shape of additional data stored alongside the authorization
 *   request. Defaults to {@link AuthorizationCodeReqData}.
 *
 * @example
 * ```ts
 * const flow = new AuthorizationCodeFlowBuilder({ tokenEndpoint: "/token" })
 *   .setAuthorizationEndpoint("/authorize")
 *   .getClient(async ({ clientId }) => db.findClient(clientId))
 *   .getClientForAuthentication(async ({ clientId }) => db.findClient(clientId))
 *   .getUserForAuthentication(async (ctx, data) => auth.verify(data))
 *   .generateAuthorizationCode(async (ctx) => crypto.randomUUID())
 *   .generateAccessToken(async (ctx) => ({ accessToken: issueToken(ctx) }))
 *   .build();
 * ```
 */
export class AuthorizationCodeFlowBuilder<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends OAuth2FlowBuilder {
  protected model: AuthorizationCodeModel<AuthReqData>;
  protected authorizationEndpoint?: string;

  /**
   * Creates a new `AuthorizationCodeFlowBuilder` with the given partial options.
   * All model callbacks default to no-op implementations and must be replaced
   * with the appropriate setter methods before calling {@link build}.
   * @param params - Partial flow options; `model` and `authorizationEndpoint` are
   *   extracted and managed separately from the base builder params.
   */
  constructor(params: Partial<AuthorizationCodeFlowOptions<AuthReqData>>) {
    const { model, authorizationEndpoint, ...rest } = params;
    super(rest);
    this.model = model || {
      generateAccessToken() {
        return undefined;
      },
      generateAuthorizationCode() {
        return undefined;
      },
      getClient() {
        return undefined;
      },
      getClientForAuthentication() {
        return undefined;
      },
      getUserForAuthentication() {
        return undefined;
      },
    };
    this.authorizationEndpoint = authorizationEndpoint;
  }

  /**
   * Sets the URL of the authorization endpoint where the authorization code request
   * is initiated (e.g. `/authorize`).
   * @param url - The authorization endpoint URL.
   * @returns `this` for chaining.
   */
  setAuthorizationEndpoint(url: string): this {
    this.authorizationEndpoint = url;
    return this;
  }

  /**
   * Returns the configured authorization endpoint URL.
   * @returns The authorization endpoint URL, or `undefined` if not set.
   */
  getAuthorizationEndpoint(): string | undefined {
    return this.authorizationEndpoint;
  }

  /**
   * Sets the model callback responsible for generating an access token (and optionally
   * a refresh token) after the authorization code has been exchanged.
   * @param handler - The access token generation function.
   * @returns `this` for chaining.
   */
  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      AuthorizationCodeGrantContext,
      AuthorizationCodeAccessTokenResult | string
    >,
  ): this {
    this.model.generateAccessToken = handler;
    return this;
  }

  /**
   * Sets the model callback responsible for generating a new access token when a
   * refresh token is presented at the token endpoint.
   * @param handler - The refresh-token-to-access-token generation function.
   * @returns `this` for chaining.
   */
  generateAccessTokenFromRefreshToken(
    handler: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
      AuthorizationCodeAccessTokenResult | string
    >,
  ): this {
    this.model.generateAccessTokenFromRefreshToken = handler;
    return this;
  }

  /**
   * Sets the model callback responsible for generating and persisting the authorization code
   * returned to the client at the authorization endpoint.
   * @param handler - The authorization code generation function.
   * @returns `this` for chaining.
   */
  generateAuthorizationCode(
    handler: GenerateAuthorizationCodeFunction<AuthorizationCodeEndpointContext>,
  ): this {
    this.model.generateAuthorizationCode = handler;
    return this;
  }

  /**
   * Sets the model callback used to look up a client by ID (and optionally secret)
   * at the token endpoint.
   * @param handler - The client lookup function for token requests and refresh token requests.
   * @returns `this` for chaining.
   */
  getClient(
    handler: OAuth2GetClientFunction<AuthorizationCodeTokenRequest | OAuth2RefreshTokenRequest>,
  ): this {
    this.model.getClient = handler;
    return this;
  }

  /**
   * Sets the model callback used to look up a client during the authorization endpoint
   * request (before the user authenticates).
   * @param handler - The client lookup function for authorization endpoint requests.
   * @returns `this` for chaining.
   */
  getClientForAuthentication(
    handler: OAuth2GetClientFunction<AuthorizationCodeEndpointRequest>,
  ): this {
    this.model.getClientForAuthentication = handler;
    return this;
  }

  /**
   * Sets the model callback responsible for authenticating the end user and returning
   * their identity, given the authorization request context and any additional request data.
   * @param handler - The user authentication function.
   * @returns `this` for chaining.
   */
  getUserForAuthentication(
    handler: GetUserForAuthenticationFunction<
      AuthorizationCodeEndpointContext,
      AuthReqData
    >,
  ): this {
    this.model.getUserForAuthentication = handler;
    return this;
  }

  /**
   * Assembles the complete {@link AuthorizationCodeFlowOptions} from the builder state.
   * @returns The options object passed to the `AuthorizationCodeFlow` constructor.
   */
  protected override buildParams(): AuthorizationCodeFlowOptions<AuthReqData> {
    return {
      ...super.buildParams(),
      model: this.model,
      authorizationEndpoint: this.authorizationEndpoint,
    };
  }

  /**
   * Constructs and returns a fully configured {@link AuthorizationCodeFlow} instance.
   * @returns A new `AuthorizationCodeFlow` ready for use in a route handler.
   */
  override build(): AuthorizationCodeFlow<AuthReqData> {
    return new AuthorizationCodeFlow<AuthReqData>(this.buildParams());
  }
}
