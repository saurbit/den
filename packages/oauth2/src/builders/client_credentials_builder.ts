/**
 * @module client_credentials_builder
 * @description Fluent builder for constructing {@link ClientCredentialsFlow} instances.
 * Provides setter methods for the model callbacks required by the Client Credentials
 * grant — a machine-to-machine flow with no end-user involvement.
 */

import {
  ClientCredentialsFlow,
  ClientCredentialsFlowOptions,
  ClientCredentialsGrantContext,
  ClientCredentialsModel,
  ClientCredentialsTokenRequest,
} from "../grants/client_credentials.ts";
import {
  OAuth2AccessTokenResult,
  OAuth2GenerateAccessTokenFunction,
  OAuth2GetClientFunction,
} from "../grants/flow.ts";
import { OAuth2FlowBuilder } from "./flow_builder.ts";

/**
 * Fluent builder for {@link ClientCredentialsFlow}.
 *
 * Collects the required model callbacks through chainable setter methods, then
 * produces a fully configured `ClientCredentialsFlow` instance via {@link build}.
 *
 * Note: the `none` client authentication method is intentionally disabled for this
 * flow — client credentials require the client to authenticate with a secret.
 *
 * @example
 * ```ts
 * const flow = new ClientCredentialsFlowBuilder({ tokenEndpoint: "/token" })
 *   .setScopes({ "read:data": "Read access to data" })
 *   .clientSecretBasicAuthenticationMethod()
 *   .getClient(async ({ clientId, clientSecret }) => db.findClient(clientId, clientSecret))
 *   .generateAccessToken(async (ctx) => ({ accessToken: issueToken(ctx) }))
 *   .build();
 * ```
 */
export class ClientCredentialsFlowBuilder extends OAuth2FlowBuilder {
  protected model: ClientCredentialsModel;

  /**
   * Creates a new `ClientCredentialsFlowBuilder` with the given partial options.
   * Model callbacks default to no-op implementations and must be replaced with the
   * appropriate setter methods before calling {@link build}.
   * @param params - Partial flow options; `model` is extracted and managed separately
   *   from the base builder params.
   */
  constructor(params: Partial<ClientCredentialsFlowOptions>) {
    const { model, ...rest } = params;
    super(rest);
    this.model = model || {
      generateAccessToken() {
        return undefined;
      },
      getClient() {
        return undefined;
      },
    };
  }

  /**
   * Disabled for the Client Credentials flow. Client credentials require the client
   * to authenticate with a secret, so the `none` method is not supported.
   * Calling this method has no effect.
   * @returns `this` for chaining.
   */
  override noneAuthenticationMethod(): this {
    return this;
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
   * Assembles the complete {@link ClientCredentialsFlowOptions} from the builder state.
   * @returns The options object passed to the `ClientCredentialsFlow` constructor.
   */
  protected override buildParams(): ClientCredentialsFlowOptions {
    return {
      ...super.buildParams(),
      model: this.model,
    };
  }

  /**
   * Constructs and returns a fully configured {@link ClientCredentialsFlow} instance.
   * @returns A new `ClientCredentialsFlow` ready for use in a route handler.
   */
  build(): ClientCredentialsFlow {
    return new ClientCredentialsFlow(
      this.buildParams(),
    );
  }
}
