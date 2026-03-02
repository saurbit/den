import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

export class ClientSecretBasic implements ClientAuthMethod {
    get method(): 'client_secret_basic' {
        return 'client_secret_basic';
    }

    get secretIsOptional(): boolean {
        return false;
    }

    extractParams(request: Request): ClientAuthMethodResponse {
        const res: ClientAuthMethodResponse = {
            hasAuthMethod: false,
        };

        const authorization = request.headers.get("authorization");

        const [authType = '', base64Credentials = ''] = authorization ? authorization.split(/\s+/) : ['', ''];

        if (authType.toLowerCase() == 'basic') {
            res.hasAuthMethod = true;

            const binary = atob(base64Credentials);
            const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
            const [clientId, clientSecret] = new TextDecoder().decode(bytes).split(":");

            if (clientId) {
                res.clientId = clientId;
            }
            if (clientSecret) {
                res.clientSecret = clientSecret;
            }
        }

        return res;
    }
}