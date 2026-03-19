import { OAuth2Error } from "../errors.ts";
import { OAuth2Client } from "../types.ts";
import {
  OAuth2AccessTokenResult,
  OAuth2FlowOptions,
  OAuth2GetClientFunction,
  OAuth2GrantModel,
  OAuth2RefreshTokenRequest,
} from "./flow.ts";

export interface DeviceAuthorizationUser {
  [key: string]: unknown;
}

export interface DeviceAuthorizationReqData {
  [key: string]: unknown;
}

export interface DeviceAuthorizationGrant {
  /** The grant type identifier. */
  readonly grantType: "urn:ietf:params:oauth:grant-type:device_code";
}

export interface DeviceAuthorizationGrantContext {
  client: OAuth2Client;
  grantType: "urn:ietf:params:oauth:grant-type:device_code";
  tokenType: string;
  accessTokenLifetime: number;
  interval: number;
  deviceCode: string;
}

/**
 * Raw token request parameters for device code grant.
 */
export interface DeviceAuthorizationTokenRequest {
  clientId: string;
  grantType: "urn:ietf:params:oauth:grant-type:device_code";
  deviceCode: string;
  clientSecret?: string;
}

export interface DeviceAuthorizationEndpointContext {
  client: OAuth2Client;
  scope: string[];
  tokenType: string;
  accessTokenLifetime: number;
  interval: number;
  verificationUri?: string;
}

/**
 * Raw authentication request parameters for device code grant.
 */
export interface DeviceAuthorizationEndpointRequest {
  clientId: string;
  clientSecret?: string;
  scope?: string[];
}

export interface DeviceAuthorizationEndpointCodeResponse<
  C extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> {
  context: C;
  user: DeviceAuthorizationUser;
  deviceCode: string;
  userCode: string;
  verificationUriComplete?: string;
  error?: never;
  [key: string]: unknown;
}

export type DeviceAuthorizationProcessResponse<
  C extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> =
  | {
    type: "device_code";
    deviceCodeResponse: DeviceAuthorizationEndpointCodeResponse<C>;
  }
  | {
    type: "error";
    error: OAuth2Error;
    client?: OAuth2Client;
  };

export interface DeviceAuthorizationAccessTokenResult extends OAuth2AccessTokenResult {
  /**
   * Necessary to return the scope to the client.
   */
  scope?: string[];

  refreshToken?: string;

  /**
   * For OpenID Connect, an ID token can also be returned from the token endpoint when exchanging the authorization code for tokens, and it should be included in the access token result so that it can be returned to the client in the token response.
   * @see https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
   */
  idToken?: string;
}

export interface GenerateDeviceCodeFunction<
  TContext extends DeviceAuthorizationEndpointContext = DeviceAuthorizationEndpointContext,
> {
  (
    context: TContext,
  ):
    | Promise<string | undefined>
    | string
    | undefined;
}

/**
 * Model interface that must be implemented by the consuming application
 * to provide persistence for clients and tokens related to the device authorization grant.
 */
export interface DeviceAuthorizationModel<
  AuthReqData extends DeviceAuthorizationReqData = DeviceAuthorizationReqData,
> extends
  OAuth2GrantModel<
    DeviceAuthorizationTokenRequest | OAuth2RefreshTokenRequest,
    DeviceAuthorizationGrantContext,
    DeviceAuthorizationAccessTokenResult | string
  > {
  /**
   * Retrieve and validate the client for an authorization code or refresh token request.
   *
   * When `tokenRequest.grantType === "authorization_code"`, implementations MUST:
   * 1. Verify the `code` is valid and has not already been used (one-time use).
   * 2. Verify the `clientId` matches the client that requested the code.
   * 3. If `redirectUri` is present, verify it is identical to the `redirect_uri`
   *    used in the original authorization request (RFC 6749 §4.1.3). Omitting
   *    this check enables authorization code injection attacks.
   * 4. If `codeVerifier` is present, verify it against the stored `code_challenge`
   *    using the stored `code_challenge_method` (RFC 7636 §4.6).
   *
   * @see https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
   * @see https://datatracker.ietf.org/doc/html/rfc7636#section-4.6
   */
  getClient: OAuth2GetClientFunction<DeviceAuthorizationTokenRequest | OAuth2RefreshTokenRequest>;

  getClientForAuthentication: OAuth2GetClientFunction<DeviceAuthorizationEndpointRequest>;

  /*
  getUser()
  getUserForAuthentication: GetUserForAuthenticationFunction<
    DeviceAuthorizationEndpointContext,
    AuthReqData
  >;
  */

  generateDeviceCode: GenerateDeviceCodeFunction<DeviceAuthorizationEndpointContext>;
}

/**
 * Options for configuring the device authorization grant flow.
 */
export interface DeviceAuthorizationFlowOptions<
  AuthReqData extends DeviceAuthorizationReqData = DeviceAuthorizationReqData,
> extends OAuth2FlowOptions {
  model: DeviceAuthorizationModel<AuthReqData>;
  authorizationEndpoint?: string;
}
