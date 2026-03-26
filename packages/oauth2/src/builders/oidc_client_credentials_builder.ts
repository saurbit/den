/**
 * @module oidc_client_credentials_builder
 * @description Fluent builder for constructing {@link OIDCClientCredentialsFlow} instances.
 * Extends the base Client Credentials builder with OIDC-specific endpoints (discovery,
 * JWKS) and an optional static OpenID configuration override for the discovery document.
 * Because this is a machine-to-machine flow, ID tokens and UserInfo endpoints are not used.
 */

import {
  ClientCredentialsGrantContext,
  ClientCredentialsModel,
  ClientCredentialsTokenRequest,
} from "../grants/client_credentials.ts";
import {
  OAuth2AccessTokenResult,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
} from "../grants/flow.ts";
import {
  OIDCClientCredentialsFlow,
  OIDCClientCredentialsFlowOptions,
} from "../oidc/oidc_client_credentials.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

/**
 * Fluent builder for {@link OIDCClientCredentialsFlow}.
 *
 * Extends {@link OAuth2FlowBuilder} with OIDC-specific configuration: discovery URL,
 * optional JWKS endpoint, and optional static OpenID configuration overrides. All model
 * callbacks are set through chainable setter methods and the flow is produced via {@link build}.
 *
 * Note: the `none` client authentication method is disabled - client credentials require
 * the client to authenticate with a secret.
 *
 * @example
 * ```ts
 * const flow = new OIDCClientCredentialsFlowBuilder({ tokenEndpoint: "/token" })
 *   .setDiscoveryUrl("/.well-known/openid-configuration")
 *   .setJwksEndpoint("/.well-known/jwks.json")
 *   .clientSecretBasicAuthenticationMethod()
 *   .getClient(async ({ clientId, clientSecret }) => db.findClient(clientId, clientSecret))
 *   .generateAccessToken(async (ctx) => ({ accessToken: issueToken(ctx) }))
 *   .build();
 * ```
 */
export class OIDCClientCredentialsFlowBuilder extends OAuth2FlowBuilder {
  protected model: ClientCredentialsModel;
  protected discoveryUrl: string;
  protected jwksEndpoint?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  /**
   * Creates a new `OIDCClientCredentialsFlowBuilder` with the given partial options.
   * `discoveryUrl` defaults to `"/.well-known/openid-configuration"` if not provided.
   * All model callbacks default to no-op implementations and must be replaced with the
   * appropriate setter methods before calling {@link build}.
   * @param params - Partial flow options; OIDC-specific fields and `model` are extracted
   *   and managed separately from the base builder params.
   */
  constructor(params: Partial<OIDCClientCredentialsFlowOptions>) {
    const { model, discoveryUrl, jwksEndpoint, openIdConfiguration, ...rest } = params;
    super(rest);
    this.model = model || {
      generateAccessToken() {
        return undefined;
      },
      getClient() {
        return undefined;
      },
    };
    this.discoveryUrl = discoveryUrl || "/.well-known/openid-configuration";
    this.jwksEndpoint = jwksEndpoint;
    this.openIdConfiguration = openIdConfiguration;
  }

  /**
   * Disabled for the OIDC Client Credentials flow. Client credentials require the client
   * to authenticate with a secret, so the `none` method is not supported.
   * Calling this method has no effect.
   * @returns `this` for chaining.
   */
  override noneAuthenticationMethod(): this {
    return this;
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
   * May be an absolute URL or a relative path resolved against the discovery URL's origin.
   * @param url - The JWKS endpoint URL (e.g. `"/.well-known/jwks.json"`).
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
   * @returns The JWKS endpoint URL, or `undefined` if not set.
   */
  getJwksEndpoint(): string | undefined {
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
   * Sets the model callback used to look up and authenticate a client by its ID and
   * secret at the token endpoint.
   * @param handler - The client lookup function for client credentials token requests.
   * @returns `this` for chaining.
   */
  getClient(handler: OAuth2GetClientFunction<ClientCredentialsTokenRequest>): this {
    this.model.getClient = handler;
    return this;
  }

  /**
   * Sets the model callback responsible for generating an access token for the
   * authenticated client.
   * @param handler - The access token generation function.
   * @returns `this` for chaining.
   */
  generateAccessToken(
    handler: OAuth2GenerateAccessTokenFunction<
      ClientCredentialsGrantContext,
      OAuth2AccessTokenResult | string
    >,
  ): this {
    this.model.generateAccessToken = handler;
    return this;
  }

  /**
   * Assembles the complete {@link OIDCClientCredentialsFlowOptions} from the builder state.
   * @returns The options object passed to the `OIDCClientCredentialsFlow` constructor.
   */
  protected override buildParams(): OIDCClientCredentialsFlowOptions {
    return {
      ...super.buildParams(),
      model: this.model,
      discoveryUrl: this.discoveryUrl,
      jwksEndpoint: this.jwksEndpoint,
      openIdConfiguration: this.openIdConfiguration,
    };
  }

  /**
   * Constructs and returns a fully configured {@link OIDCClientCredentialsFlow} instance.
   * @returns A new `OIDCClientCredentialsFlow` ready for use in a route handler.
   */
  build(): OIDCClientCredentialsFlow {
    return new OIDCClientCredentialsFlow(
      this.buildParams(),
    );
  }
}
