/**
 * @module device_authorization_builder
 * @description Fluent builder for constructing {@link DeviceAuthorizationFlow} instances.
 * Provides setter methods for every model callback required by the Device Authorization
 * grant (RFC 8628), including device code generation, user code verification, and
 * refresh token handling.
 */

import {
  DeviceAuthorizationAccessTokenError,
  DeviceAuthorizationAccessTokenResult,
  DeviceAuthorizationEndpointContext,
  DeviceAuthorizationEndpointRequest,
  DeviceAuthorizationFlow,
  DeviceAuthorizationFlowOptions,
  DeviceAuthorizationGrantContext,
  DeviceAuthorizationModel,
  DeviceAuthorizationTokenRequest,
  GenerateDeviceCodeFunction,
} from "../grants/device_authorization.ts";
import {
  OAuth2GenerateAccessTokenFromRefreshTokenFunction,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
  OAuth2RefreshTokenRequest,
} from "../grants/flow.ts";
import { OAuth2Client } from "../types.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

/**
 * Fluent builder for {@link DeviceAuthorizationFlow}.
 *
 * Collects all required model callbacks and configuration options through chainable
 * setter methods, then produces a fully configured `DeviceAuthorizationFlow` instance
 * via {@link build}.
 *
 * @example
 * ```ts
 * const flow = new DeviceAuthorizationFlowBuilder({ tokenEndpoint: "/token" })
 *   .setAuthorizationEndpoint("/device/authorize")
 *   .setVerificationEndpoint("/device/verify")
 *   .getClient(async ({ clientId }) => db.findClient(clientId))
 *   .getClientForAuthentication(async ({ clientId }) => db.findClient(clientId))
 *   .generateDeviceCode(async (ctx) => ({ deviceCode: crypto.randomUUID(), userCode: "ABCD-1234", expiresIn: 300 }))
 *   .verifyUserCode(async (userCode) => db.findDeviceCodeByUserCode(userCode))
 *   .generateAccessToken(async (ctx) => ({ accessToken: issueToken(ctx) }))
 *   .build();
 * ```
 */
export class DeviceAuthorizationFlowBuilder extends OAuth2FlowBuilder {
  protected model: DeviceAuthorizationModel;
  protected authorizationEndpoint?: string;
  protected verificationEndpoint?: string;

  /**
   * Creates a new `DeviceAuthorizationFlowBuilder` with the given partial options.
   * All model callbacks default to no-op implementations and must be replaced
   * with the appropriate setter methods before calling {@link build}.
   * @param params - Partial flow options; `model`, `authorizationEndpoint`, and
   *   `verificationEndpoint` are extracted and managed separately from the base builder params.
   */
  constructor(params: Partial<DeviceAuthorizationFlowOptions>) {
    const { model, authorizationEndpoint, verificationEndpoint, ...rest } = params;
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
   * Sets the model callback responsible for generating an access token (and optionally
   * a refresh token) after the user has authorized the device.
   * The result may also be a {@link DeviceAuthorizationAccessTokenError} to signal
   * that authorization is still pending or has been declined.
   * @param handler - The access token generation function.
   * @returns `this` for chaining.
   */
  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      DeviceAuthorizationGrantContext,
      DeviceAuthorizationAccessTokenResult | DeviceAuthorizationAccessTokenError
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
   * Assembles the complete {@link DeviceAuthorizationFlowOptions} from the builder state.
   * @returns The options object passed to the `DeviceAuthorizationFlow` constructor.
   */
  protected override buildParams(): DeviceAuthorizationFlowOptions {
    return {
      ...super.buildParams(),
      model: this.model,
      authorizationEndpoint: this.authorizationEndpoint,
      verificationEndpoint: this.verificationEndpoint,
    };
  }

  /**
   * Constructs and returns a fully configured {@link DeviceAuthorizationFlow} instance.
   * @returns A new `DeviceAuthorizationFlow` ready for use in a route handler.
   */
  override build(): DeviceAuthorizationFlow {
    return new DeviceAuthorizationFlow(this.buildParams());
  }
}
