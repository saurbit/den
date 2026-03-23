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

export class DeviceAuthorizationFlowBuilder extends OAuth2FlowBuilder {
  protected model: DeviceAuthorizationModel;
  protected authorizationEndpoint?: string;
  protected verificationEndpoint?: string;

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

  setAuthorizationEndpoint(url: string): this {
    this.authorizationEndpoint = url;
    return this;
  }

  getAuthorizationEndpoint(): string | undefined {
    return this.authorizationEndpoint;
  }

  setVerificationEndpoint(url: string): this {
    this.verificationEndpoint = url;
    return this;
  }

  getVerificationEndpoint(): string | undefined {
    return this.verificationEndpoint;
  }

  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      DeviceAuthorizationGrantContext,
      DeviceAuthorizationAccessTokenResult | DeviceAuthorizationAccessTokenError
    >,
  ): this {
    this.model.generateAccessToken = handler;
    return this;
  }

  generateAccessTokenFromRefreshToken(
    handler: OAuth2GenerateAccessTokenFromRefreshTokenFunction<
      DeviceAuthorizationAccessTokenResult
    >,
  ): this {
    this.model.generateAccessTokenFromRefreshToken = handler;
    return this;
  }

  generateDeviceCode(
    handler: GenerateDeviceCodeFunction<DeviceAuthorizationEndpointContext>,
  ): this {
    this.model.generateDeviceCode = handler;
    return this;
  }

  getClient(
    handler: OAuth2GetClientFunction<DeviceAuthorizationTokenRequest | OAuth2RefreshTokenRequest>,
  ): this {
    this.model.getClient = handler;
    return this;
  }

  getClientForAuthentication(
    handler: OAuth2GetClientFunction<DeviceAuthorizationEndpointRequest>,
  ): this {
    this.model.getClientForAuthentication = handler;
    return this;
  }

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

  protected override buildParams(): DeviceAuthorizationFlowOptions {
    return {
      ...super.buildParams(),
      model: this.model,
      authorizationEndpoint: this.authorizationEndpoint,
      verificationEndpoint: this.verificationEndpoint,
    };
  }

  override build(): DeviceAuthorizationFlow {
    return new DeviceAuthorizationFlow(this.buildParams());
  }
}
