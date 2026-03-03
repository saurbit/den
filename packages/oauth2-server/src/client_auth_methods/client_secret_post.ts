import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

export class ClientSecretPost implements ClientAuthMethod {
    get method(): 'client_secret_post' {
        return 'client_secret_post';
    }

    get secretIsOptional(): boolean {
        return false;
    }

    async extractClientCredentials(req: Request): Promise<ClientAuthMethodResponse> {
        const res: ClientAuthMethodResponse = {
            hasAuthMethod: false,
        };

        const contentType = req.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
            return res; // Only process JSON requests for client secret post authentication
        }

        const body: unknown = req.json ? await req.json() : null;

        if (
            body &&
            typeof body === 'object' &&
            'client_id' in body &&
            'client_secret' in body
        ) {
            res.hasAuthMethod = true;
            if (typeof body.client_id === 'string') res.clientId = body.client_id;
            if (typeof body.client_secret === 'string') res.clientSecret = body.client_secret;
        }

        return res;
    }
}