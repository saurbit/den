import {
  AbstractClientCredentialsFlow,
  ClientCredentialsFlowOptions,
} from "../grants/client_credentials.ts";
import { normalizeUrl } from "../utils/normalize_url.ts";
import { OIDCFlow, OIDCFlowExtendedOptions } from "./types.ts";

/**
 * Options for configuring the client credentials grant flow.
 */
export interface OIDCClientCredentialsFlowOptions
  extends ClientCredentialsFlowOptions, OIDCFlowExtendedOptions {
}

export class OIDCClientCredentialsFlow extends AbstractClientCredentialsFlow implements OIDCFlow {
  protected discoveryUrl: string;
  protected jwksEndpoint?: string;
  protected openIdConfiguration?: Record<string, string | string[] | undefined>;

  constructor(options: OIDCClientCredentialsFlowOptions) {
    const { discoveryUrl, jwksEndpoint, openIdConfiguration, ...baseOptions } = options;
    super(baseOptions);
    this.discoveryUrl = discoveryUrl;
    this.jwksEndpoint = jwksEndpoint;
    this.openIdConfiguration = openIdConfiguration;
  }

  protected normalizeUrl(url: string, origin?: string): string {
    return normalizeUrl(url, origin || new URL(this.discoveryUrl).origin);
  }

  getDiscoveryUrl(): string {
    return this.discoveryUrl;
  }

  getJwksUri(): string | undefined {
    return this.jwksEndpoint;
  }

  getOpenIdConfiguration(): Record<string, string | string[] | undefined> | undefined {
    return this.openIdConfiguration;
  }

  toOpenAPISecurityScheme() {
    return {
      [this.getSecuritySchemeName()]: {
        type: "openIdConnect" as const,
        description: this.getDescription(),
        openIdConnectUrl: this.getDiscoveryUrl(),
      },
    };
  }

  getDiscoveryConfiguration() {
    const supported = this.getTokenEndpointAuthMethods();
    const scopes = this.getScopes() || {};

    const host = new URL(this.getDiscoveryUrl()).origin;

    // Format jwks_uri if it's a relative path
    let jwksEndpoint = this.getJwksUri();
    if (jwksEndpoint) {
      jwksEndpoint = this.normalizeUrl(jwksEndpoint, host);
    }
    // Format token endpoint if it's a relative path
    let tokenEndpoint = this.getTokenUrl();
    if (tokenEndpoint) {
      tokenEndpoint = this.normalizeUrl(tokenEndpoint, host);
    }

    const wellKnownOpenIDConfig: Record<string, string | string[] | undefined> = {
      issuer: host,
      token_endpoint: tokenEndpoint,
      userinfo_endpoint: undefined, // irrelevant and typically not used in the client credentials flow
      jwks_uri: jwksEndpoint,
      registration_endpoint: undefined,
      claims_supported: ["aud", "exp", "iat", "iss", "sub"],
      grant_types_supported: [this.grantType],
      response_types_supported: ["token"],
      scopes_supported: Object.keys(scopes),
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: supported,
    };

    if (this.clientAuthMethods.client_secret_jwt?.algorithms?.length) {
      wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported =
        wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported || [];
      wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported = [
        ...wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported,
        ...this.clientAuthMethods.client_secret_jwt.algorithms,
      ];
    }
    if (this.clientAuthMethods.private_key_jwt?.algorithms?.length) {
      wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported =
        wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported || [];
      wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported = [
        ...wellKnownOpenIDConfig.token_endpoint_auth_signing_alg_values_supported,
        ...this.clientAuthMethods.private_key_jwt.algorithms,
      ];
    }

    const result = { ...wellKnownOpenIDConfig, ...(this.getOpenIdConfiguration() || {}) };

    // Format unhandled endpoints
    if (typeof result.userinfo_endpoint === "string") {
      result.userinfo_endpoint = this.normalizeUrl(result.userinfo_endpoint, host);
    }
    if (typeof result.registration_endpoint === "string") {
      result.registration_endpoint = this.normalizeUrl(result.registration_endpoint, host);
    }

    return result;
  }
}
