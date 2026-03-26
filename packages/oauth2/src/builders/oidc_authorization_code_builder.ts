/**
 * @module oidc_authorization_code_builder
 * @description Fluent builder for constructing {@link OIDCAuthorizationCodeFlow} instances.
 * Extends the base Authorization Code builder with OIDC-specific endpoints (discovery,
 * JWKS, UserInfo, registration) and enforces ID token generation in the access token callback.
 */

import {
  AuthorizationCodeAccessTokenResult,
  AuthorizationCodeGrantContext,
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
import {
  OIDCAuthorizationCodeAccessTokenResult,
  OIDCAuthorizationCodeEndpointContext,
  OIDCAuthorizationCodeEndpointRequest,
  OIDCAuthorizationCodeFlow,
  OIDCAuthorizationCodeFlowOptions,
  OIDCAuthorizationCodeModel,
} from "../oidc/oidc_authorization_code.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

/**
 * Fluent builder for {@link OIDCAuthorizationCodeFlow}.
 *
 * Extends {@link OAuth2FlowBuilder} with OIDC-specific configuration: discovery URL,
 * JWKS endpoint, UserInfo endpoint, registration endpoint, and optional static OpenID
 * configuration overrides. All model callbacks are set through chainable setter methods
 * and the flow is produced via {@link build}.
 *
 * The `generateAccessToken` callback **must** return an `idToken` field in its result,
 * as the OIDC Authorization Code flow enforces ID token presence in every token response.
 *
 * @template AuthReqData - The shape of additional data stored alongside the authorization
 *   request. Defaults to {@link AuthorizationCodeReqData}.
 *
 * @example
 * ```ts
 * const flow = new OIDCAuthorizationCodeFlowBuilder({ tokenEndpoint: "/token" })
 *   .setDiscoveryUrl("/.well-known/openid-configuration")
 *   .setJwksEndpoint("/.well-known/jwks.json")
 *   .setAuthorizationEndpoint("/authorize")
 *   .setUserInfoEndpoint("/userinfo")
 *   .getClient(async ({ clientId }) => db.findClient(clientId))
 *   .getClientForAuthentication(async ({ clientId }) => db.findClient(clientId))
 *   .getUserForAuthentication(async (ctx, data) => auth.verify(data))
 *   .generateAuthorizationCode(async (ctx) => crypto.randomUUID())
 *   .generateAccessToken(async (ctx) => ({ accessToken: issueToken(ctx), idToken: signIdToken(ctx) }))
 *   .build();
 * ```
 */
export class OIDCAuthorizationCodeFlowBuilder<
  AuthReqData extends AuthorizationCodeReqData = AuthorizationCodeReqData,
> extends OAuth2FlowBuilder {
  protected model: OIDCAuthorizationCodeModel<AuthReqData>;
  protected discoveryUrl: string;
  protected jwksEndpoint: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;
  protected authorizationEndpoint?: string;
  protected userInfoEndpoint?: string;
  protected registrationEndpoint?: string;

  /**
   * Creates a new `OIDCAuthorizationCodeFlowBuilder` with the given partial options.
   * OIDC-specific fields default to standard well-known paths:
   * - `discoveryUrl` → `"/.well-known/openid-configuration"`
   * - `jwksEndpoint` → `"/.well-known/jwks.json"`
   *
   * All model callbacks default to no-op implementations and must be replaced with the
   * appropriate setter methods before calling {@link build}.
   * @param params - Partial flow options; OIDC-specific fields and `model` are extracted
   *   and managed separately from the base builder params.
   */
  constructor(params: Partial<OIDCAuthorizationCodeFlowOptions<AuthReqData>>) {
    const {
      model,
      authorizationEndpoint,
      discoveryUrl,
      jwksEndpoint,
      userInfoEndpoint,
      registrationEndpoint,
      openIdConfiguration,
      ...rest
    } = params;
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
    this.discoveryUrl = discoveryUrl || "/.well-known/openid-configuration";
    this.jwksEndpoint = jwksEndpoint || "/.well-known/jwks.json";
    this.openIdConfiguration = openIdConfiguration;
    this.authorizationEndpoint = authorizationEndpoint;
    this.userInfoEndpoint = userInfoEndpoint;
    this.registrationEndpoint = registrationEndpoint;
  }

  /**
   * Sets the OIDC discovery document URL (the `/.well-known/openid-configuration` endpoint).
   * @param url - The discovery URL. Defaults to `"/.well-known/openid-configuration"`.
   * @returns `this` for chaining.
   */
  setDiscoveryUrl(url: string): this {
    this.discoveryUrl = url;
    return this;
  }

  /**
   * Sets the JWKS endpoint URL used to publish the provider's public signing keys.
   * @param url - The JWKS endpoint URL. Defaults to `"/.well-known/jwks.json"`.
   * @returns `this` for chaining.
   */
  setJwksEndpoint(url: string): this {
    this.jwksEndpoint = url;
    return this;
  }

  /**
   * Sets static OpenID Connect configuration overrides that are merged into the
   * discovery document produced by `getDiscoveryConfiguration()`.
   * @param config - A record of provider metadata fields to override or extend.
   * @returns `this` for chaining.
   */
  setOpenIdConfiguration(config: Record<string, string | string[] | undefined>): this {
    this.openIdConfiguration = config;
    return this;
  }

  /**
   * Returns the configured discovery URL.
   * @returns The discovery URL.
   */
  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  /**
   * Returns the configured JWKS endpoint URL.
   * @returns The JWKS endpoint URL.
   */
  getJwksEndpoint(): string {
    return this.jwksEndpoint;
  }

  /**
   * Returns any static OpenID Connect configuration overrides.
   * @returns The static OpenID configuration map, or `undefined` if none was set.
   */
  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  /**
   * Sets the URL of the authorization endpoint where the OIDC authentication request
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
   * Sets the URL of the UserInfo endpoint where clients can retrieve claims about
   * the authenticated end user.
   * @param url - The UserInfo endpoint URL (e.g. `/userinfo`).
   * @returns `this` for chaining.
   */
  setUserInfoEndpoint(url: string): this {
    this.userInfoEndpoint = url;
    return this;
  }

  /**
   * Returns the configured UserInfo endpoint URL.
   * @returns The UserInfo endpoint URL, or `undefined` if not set.
   */
  getUserInfoEndpoint(): string | undefined {
    return this.userInfoEndpoint;
  }

  /**
   * Sets the URL of the dynamic client registration endpoint.
   * @param url - The registration endpoint URL (e.g. `/register`).
   * @returns `this` for chaining.
   */
  setRegistrationEndpoint(url: string): this {
    this.registrationEndpoint = url;
    return this;
  }

  /**
   * Returns the configured dynamic client registration endpoint URL.
   * @returns The registration endpoint URL, or `undefined` if not set.
   */
  getRegistrationEndpoint(): string | undefined {
    return this.registrationEndpoint;
  }

  /**
   * Sets the model callback responsible for generating an access token and the required
   * OIDC ID token after the authorization code has been exchanged.
   * The result **must** include an `idToken` field.
   * @param handler - The access token (+ ID token) generation function.
   * @returns `this` for chaining.
   */
  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      AuthorizationCodeGrantContext,
      OIDCAuthorizationCodeAccessTokenResult
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
      AuthorizationCodeAccessTokenResult
    >,
  ): this {
    this.model.generateAccessTokenFromRefreshToken = handler;
    return this;
  }

  /**
   * Sets the model callback responsible for generating and persisting the authorization
   * code returned to the client at the authorization endpoint.
   * @param handler - The authorization code generation function, receiving the full
   *   OIDC authorization endpoint context including OIDC-specific request parameters.
   * @returns `this` for chaining.
   */
  generateAuthorizationCode(
    handler: GenerateAuthorizationCodeFunction<
      OIDCAuthorizationCodeEndpointContext
    >,
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
   * Sets the model callback used to look up a client during the OIDC authorization
   * endpoint request (before the user authenticates).
   * @param handler - The client lookup function for OIDC authorization endpoint requests.
   * @returns `this` for chaining.
   */
  getClientForAuthentication(
    handler: OAuth2GetClientFunction<OIDCAuthorizationCodeEndpointRequest>,
  ): this {
    this.model.getClientForAuthentication = handler;
    return this;
  }

  /**
   * Sets the model callback responsible for authenticating the end user and returning
   * their identity, given the OIDC authorization request context and any additional
   * request data.
   * @param handler - The user authentication function.
   * @returns `this` for chaining.
   */
  getUserForAuthentication(
    handler: GetUserForAuthenticationFunction<
      OIDCAuthorizationCodeEndpointContext,
      AuthReqData
    >,
  ): this {
    this.model.getUserForAuthentication = handler;
    return this;
  }

  /**
   * Assembles the complete {@link OIDCAuthorizationCodeFlowOptions} from the builder state.
   * @returns The options object passed to the `OIDCAuthorizationCodeFlow` constructor.
   */
  protected override buildParams(): OIDCAuthorizationCodeFlowOptions<AuthReqData> {
    return {
      ...super.buildParams(),
      model: this.model,
      authorizationEndpoint: this.authorizationEndpoint,
      discoveryUrl: this.discoveryUrl,
      jwksEndpoint: this.jwksEndpoint,
      userInfoEndpoint: this.userInfoEndpoint,
      registrationEndpoint: this.registrationEndpoint,
      openIdConfiguration: this.openIdConfiguration,
    };
  }

  /**
   * Constructs and returns a fully configured {@link OIDCAuthorizationCodeFlow} instance.
   * @returns A new `OIDCAuthorizationCodeFlow` ready for use in a route handler.
   */
  override build(): OIDCAuthorizationCodeFlow<AuthReqData> {
    return new OIDCAuthorizationCodeFlow<AuthReqData>(this.buildParams());
  }
}
