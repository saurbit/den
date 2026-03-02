import { ClientAuthMethod, ClientAuthMethodResponse } from "./types.ts";

export class NoneAuthMethod implements ClientAuthMethod {
    get method(): 'none' {
        return 'none';
    }

    get secretIsOptional(): boolean {
        return true;
    }

    async extractParams(req: Request): Promise<ClientAuthMethodResponse> {
        const res: ClientAuthMethodResponse = {
            hasAuthMethod: false,
        };

        const contentType = req.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
            return res; // Only process JSON requests for none client authentication
        }

        const body: unknown = req.json ? await req.json() : null;

        if (body && typeof body === 'object' && 'client_id' in body) {
            res.hasAuthMethod = true;
            if (typeof body.client_id === 'string') res.clientId = body.client_id;
        }

        return res;
    }
}