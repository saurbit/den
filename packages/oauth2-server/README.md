# @saurbit/oauth2-server

A framework-agnostic [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) authorization server
implementation for [Deno](https://deno.land/).

## Features

- **Authorization Code** flow (with PKCE support)
- **Client Credentials** flow
- **Device Authorization** flow
- Framework-agnostic - bring your own HTTP layer
- Pluggable model interface for storage

## Quick Start

```ts
import { ClientCredentialsFlow } from "@saurbit/oauth2-server";

const flow = new ClientCredentialsFlow({
  model: {
    // implement the model interface for your storage layer
  },
  strategyOptions: {
    // implement the strategy options for your authentication strategy
  },
  // other options
});

const openAPISecurityScheme = flow.toOpenAPISecurityScheme();
```

### Use with a web framework

The library is designed to be framework-agnostic, so you can use it with any web framework by
implementing the necessary HTTP handling and model interface. For example, with
[Oak](https://deno.land/x/oak):

```ts
import { Application, Router } from "@oak/oak";
import { ClientCredentialsFlowBuilder } from "@saurbit/oauth2-server";

const flow = new ClientCredentialsFlowBuilder({
  securitySchemeName: "clientCredentials",
})
  .getClient((tokenRequest) => {
    // Implement logic to retrieve and validate the client.
    return undefined;
  })
  .generateAccessToken((grantContext) => {
    // Implement logic to generate an access token.
    return undefined;
  })
  .clientSecretBasicAuthenticationMethod()
  .build();

const router = new Router();

router.post("/token", async (ctx) => {
  try {
    const result = await flow.token(ctx.request.source as Request);
    if (!result.success) {
      ctx.response.status = result.error.statusCode || 400;
      ctx.response.body = {
        error: result.error.errorCode,
        error_description: result.error.message,
      };
    } else {
      ctx.response.status = 200;
      ctx.response.body = result.tokenResponse;
    }
  } catch (_err) {
    ctx.response.status = 500;
    ctx.response.body = { error: "Internal Server Error" };
  }
});

const app = new Application();
app.use(router.routes());
app.use(router.allowedMethods());
app.listen({ port: 8000 });
```

## License

[MIT](../../LICENSE)
