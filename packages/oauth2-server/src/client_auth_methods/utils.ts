import { TokenEndpointAuthMethod } from "./types.ts";

const sortedTokenEndpointAuthMethods: TokenEndpointAuthMethod[] = [
    'client_secret_basic',
    'client_secret_post',
    'client_secret_jwt',
    'private_key_jwt',
    'none',
];

const orderMapTokenEndpointAuthMethods = new Map(sortedTokenEndpointAuthMethods.map((item, index) => [item, index]));

export function sortTokenEndpointAuthMethods(array: TokenEndpointAuthMethod[]) {
    return array.sort((a, b) => {
        return (
            (orderMapTokenEndpointAuthMethods.get(a) ?? Infinity) -
            (orderMapTokenEndpointAuthMethods.get(b) ?? Infinity)
        );
    });
}