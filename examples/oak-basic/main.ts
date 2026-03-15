import { Application, Router } from "@oak/oak";
import { ClientCredentialsFlowBuilder } from "@saurbit/oauth2-server";

const flow = new ClientCredentialsFlowBuilder({
  securitySchemeName: "clientCredentials",
})
  .getClient((_tokenRequest) => {
    // Implement logic to retrieve and validate the client.
    return undefined;
  })
  .generateAccessToken((_grantContext) => {
    // Implement logic to generate an access token.
    return undefined;
  })
  .clientSecretBasicAuthenticationMethod()
  .build();

const router = new Router();

router.get("/", (ctx) => {
  ctx.response.body = { message: "Hello, World!" };
});

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
console.log("Server starting on http://localhost:8000");
await app.listen({ port: 8000 });
