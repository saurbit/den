/**
 * @module oidc_device_authorization_builder
 * @description Fluent builder for constructing {@link OIDCDeviceAuthorizationFlow} instances.
 * Extends the base Device Authorization builder with OIDC-specific endpoints (discovery,
 * JWKS, UserInfo, registration) and enforces ID token generation in the access token callback.
 */

import {
  DeviceAuthorizationAccessTokenError,
  DeviceAuthorizationAccessTokenResult,
  DeviceAuthorizationEndpointContext,
  DeviceAuthorizationEndpointRequest,
  DeviceAuthorizationGrantContext,
  DeviceAuthorizationTokenRequest,
  GenerateDeviceCodeFunction,
} from "../grants/device_authorization.ts";
import {
  OAuth2GenerateAccessTokenFromRefreshTokenFunction,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
  OAuth2RefreshTokenRequest,
} from "../grants/flow.ts";
import {
  OIDCDeviceAuthorizationAccessTokenResult,
  OIDCDeviceAuthorizationFlow,
  OIDCDeviceAuthorizationFlowOptions,
  OIDCDeviceAuthorizationModel,
} from "../oidc/oidc_device_authorization.ts";
import { OAuth2Client } from "../types.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

/**
 * Fluent builder for {@link OIDCDeviceAuthorizationFlow}.
 *
 * Extends {@link OAuth2FlowBuilder} with OIDC-specific configuration: discovery URL,
 * JWKS endpoint, UserInfo endpoint, registration endpoint, and optional static OpenID
 * configuration overrides. All model callbacks are set through chainable setter methods
 * and the flow is produced via {@link build}.
 *
 * The `generateAccessToken` callback **must** return an `idToken` field in its result
 * when the `openid` scope is present, as the OIDC Device Authorization flow enforces
 * ID token presence in every token response.
 *
 * @example
 * ```ts
 * const flow = new OIDCDeviceAuthorizationFlowBuilder({ tokenEndpoint: "/token" })
 *   .setDiscoveryUrl("/.well-known/openid-configuration")
 *   .setJwksEndpoint("/.well-known/jwks.json")
 *   .setAuthorizationEndpoint("/device/authorize")
 *   .setVerificationEndpoint("/device/verify")
 *   .setUserInfoEndpoint("/userinfo")
 *   .getClient(async ({ clientId }) => db.findClient(clientId))
 *   .getClientForAuthentication(async ({ clientId }) => db.findClient(clientId))
 *   .generateDeviceCode(async (ctx) => ({ deviceCode: uuid(), userCode: "ABCD-1234", expiresIn: 300 }))
 *   .verifyUserCode(async (userCode) => db.findDeviceCodeByUserCode(userCode))
 *   .generateAccessToken(async (ctx) => ({ accessToken: issueToken(ctx), idToken: signIdToken(ctx) }))
 *   .build();
 * ```
 */
export class OIDCDeviceAuthorizationFlowBuilder extends OAuth2FlowBuilder {
  protected model: OIDCDeviceAuthorizationModel;
  protected discoveryUrl: string;
  protected jwksEndpoint: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;
  protected userInfoEndpoint?: string;
  protected registrationEndpoint?: string;
  protected authorizationEndpoint?: string;
  protected verificationEndpoint?: string;

  /**
   * Creates a new `OIDCDeviceAuthorizationFlowBuilder` with the given partial options.
   * OIDC-specific fields default to standard well-known paths:
   * - `discoveryUrl` → `"/.well-known/openid-configuration"`
   * - `jwksEndpoint` → `"/.well-known/jwks.json"`
   *
   * All model callbacks default to no-op implementations and must be replaced with the
   * appropriate setter methods before calling {@link build}.
   * @param params - Partial flow options; OIDC-specific fields and `model` are extracted
   *   and managed separately from the base builder params.
   */
  constructor(params: Partial<OIDCDeviceAuthorizationFlowOptions>) {
    const {
      model,
      authorizationEndpoint,
      verificationEndpoint,
      discoveryUrl,
      jwksEndpoint,
      openIdConfiguration,
      userInfoEndpoint,
      registrationEndpoint,
      ...rest
    } = params;
    super(rest);
    this.model = model || {
      generateAccessToken() {
        return undefined;
      },
      generateDeviceCode() {
        return undefined;
      },
      getClient() {
        return undefined;
      },
      getClientForAuthentication() {
        return undefined;
      },
      verifyUserCode() {
        return undefined;
      },
    };
    this.discoveryUrl = discoveryUrl || "/.well-known/openid-configuration";
    this.jwksEndpoint = jwksEndpoint || "/.well-known/jwks.json";
    this.openIdConfiguration = openIdConfiguration;
    this.userInfoEndpoint = userInfoEndpoint;
    this.registrationEndpoint = registrationEndpoint;
    this.authorizationEndpoint = authorizationEndpoint;
    this.verificationEndpoint = verificationEndpoint;
  }

  /**
   * Sets the URL of the device authorization endpoint where the device requests
   * a device code and user code (e.g. `/device/authorize`).
   * @param url - The device authorization endpoint URL.
   * @returns `this` for chaining.
   */
  setAuthorizationEndpoint(url: string): this {
    this.authorizationEndpoint = url;
    return this;
  }

  /**
   * Returns the configured device authorization endpoint URL.
   * @returns The device authorization endpoint URL, or `undefined` if not set.
   */
  getAuthorizationEndpoint(): string | undefined {
    return this.authorizationEndpoint;
  }

  /**
   * Sets the URL of the user verification endpoint where the end user enters the
   * user code to authorize the device (e.g. `/device/verify`).
   * @param url - The verification endpoint URL.
   * @returns `this` for chaining.
   */
  setVerificationEndpoint(url: string): this {
    this.verificationEndpoint = url;
    return this;
  }

  /**
   * Returns the configured user verification endpoint URL.
   * @returns The verification endpoint URL, or `undefined` if not set.
   */
  getVerificationEndpoint(): string | undefined {
    return this.verificationEndpoint;
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
   * Returns the configured discovery URL.
   * @returns The discovery URL.
   */
  getDiscoveryUrl(): string {
    return this.discoveryUrl;
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
   * Returns the configured JWKS endpoint URL.
   * @returns The JWKS endpoint URL.
   */
  getJwksEndpoint(): string {
    return this.jwksEndpoint;
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
   * Returns any static OpenID Connect configuration overrides.
   * @returns The static OpenID configuration map, or `undefined` if none was set.
   */
  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
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
   * OIDC ID token after the user has authorized the device.
   * The result **must** include an `idToken` field when the `openid` scope is present.
   * May also return a {@link DeviceAuthorizationAccessTokenError} to signal that
   * authorization is still pending or has been declined.
   * @param handler - The access token (+ ID token) generation function.
   * @returns `this` for chaining.
   */
  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      DeviceAuthorizationGrantContext,
      OIDCDeviceAuthorizationAccessTokenResult | DeviceAuthorizationAccessTokenError
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
      DeviceAuthorizationAccessTokenResult
    >,
  ): this {
    this.model.generateAccessTokenFromRefreshToken = handler;
    return this;
  }

  /**
   * Sets the model callback responsible for generating the device code and user code
   * returned to the device at the device authorization endpoint.
   * @param handler - The device code generation function.
   * @returns `this` for chaining.
   */
  generateDeviceCode(
    handler: GenerateDeviceCodeFunction<DeviceAuthorizationEndpointContext>,
  ): this {
    this.model.generateDeviceCode = handler;
    return this;
  }

  /**
   * Sets the model callback used to look up a client by ID (and optionally secret)
   * at the token endpoint.
   * @param handler - The client lookup function for token requests and refresh token requests.
   * @returns `this` for chaining.
   */
  getClient(
    handler: OAuth2GetClientFunction<DeviceAuthorizationTokenRequest | OAuth2RefreshTokenRequest>,
  ): this {
    this.model.getClient = handler;
    return this;
  }

  /**
   * Sets the model callback used to look up a client during the device authorization
   * endpoint request (before the device code is issued).
   * @param handler - The client lookup function for device authorization endpoint requests.
   * @returns `this` for chaining.
   */
  getClientForAuthentication(
    handler: OAuth2GetClientFunction<DeviceAuthorizationEndpointRequest>,
  ): this {
    this.model.getClientForAuthentication = handler;
    return this;
  }

  /**
   * Sets the model callback used to validate a user code entered by the end user
   * at the verification endpoint, resolving it to the associated device code and client.
   * @param handler - A function that receives the user code string and returns the
   *   matching `{ deviceCode, client }` pair, or `undefined` if the code is unknown or expired.
   * @returns `this` for chaining.
   */
  verifyUserCode(
    handler: (userCode: string) =>
      | Promise<
        | { deviceCode: string; client: OAuth2Client }
        | undefined
      >
      | { deviceCode: string; client: OAuth2Client }
      | undefined,
  ): this {
    this.model.verifyUserCode = handler;
    return this;
  }

  /**
   * Assembles the complete {@link OIDCDeviceAuthorizationFlowOptions} from the builder state.
   * @returns The options object passed to the `OIDCDeviceAuthorizationFlow` constructor.
   */
  protected override buildParams(): OIDCDeviceAuthorizationFlowOptions {
    return {
      ...super.buildParams(),
      model: this.model,
      discoveryUrl: this.discoveryUrl,
      jwksEndpoint: this.jwksEndpoint,
      userInfoEndpoint: this.userInfoEndpoint,
      registrationEndpoint: this.registrationEndpoint,
      openIdConfiguration: this.openIdConfiguration,
      authorizationEndpoint: this.authorizationEndpoint,
      verificationEndpoint: this.verificationEndpoint,
    };
  }

  /**
   * Constructs and returns a fully configured {@link OIDCDeviceAuthorizationFlow} instance.
   * @returns A new `OIDCDeviceAuthorizationFlow` ready for use in a route handler.
   */
  override build(): OIDCDeviceAuthorizationFlow {
    return new OIDCDeviceAuthorizationFlow(this.buildParams());
  }
}
