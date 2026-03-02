export type TokenEndpointAuthMethod =
    | 'client_secret_basic'
    | 'client_secret_post'
    | 'client_secret_jwt'
    | 'private_key_jwt'
    | 'none';

export type OAuth2ClientAuthentication = 'body' | 'header' | TokenEndpointAuthMethod;

export interface ClientAuthMethod {
    readonly method: TokenEndpointAuthMethod;

    readonly secretIsOptional: boolean;

    readonly algorithms?: string[];

    /**
     * Extract clientId and clientSecret from the request
     */
    extractParams(request: Request): Promise<ClientAuthMethodResponse> | ClientAuthMethodResponse;
}

export type ClientAuthMethodResponse = {
    /**
     * if the authentication method is in the request
     */
    hasAuthMethod: boolean;
    clientId?: string;
    clientSecret?: string;
};

export interface ClientAuthMethod {
    readonly method: TokenEndpointAuthMethod;

    readonly secretIsOptional: boolean;

    readonly algorithms?: string[];

    /**
     * Extract clientId and clientSecret from the request
     */
    extractParams(request: Request): Promise<ClientAuthMethodResponse> | ClientAuthMethodResponse;
}