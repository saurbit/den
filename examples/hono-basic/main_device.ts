import { Hono } from "hono";
import { type } from "arktype";
import {
  describeRoute,
  openAPIRouteHandler,
  resolver,
  validator as arktypeValidator,
} from "hono-openapi";
import { swaggerUI } from "@hono/swagger-ui";
import { oauth2Redirect } from "./swagger_ui/oauth2_redirect.ts";
import { deviceAuthorizationFlow } from "./impl/device_authorization.ts";
import { UnauthorizedClientError, UnsupportedGrantTypeError } from "@saurbit/oauth2";

const app = new Hono();

app.get(
  "/",
  describeRoute({
    responses: {
      200: {
        description: "Successful response",
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                message: { type: "string" },
              },
            },
          },
        },
      },
    },
  }),
  (c) => {
    return c.json({ message: "Hello from Hono!" });
  },
);

const schema = type({
  name: "string",
  age: "number",
});

const responseSchema = type({
  success: "boolean",
  message: "string",
});

app.post(
  "/author",
  // Apply the authentication middleware to this route
  deviceAuthorizationFlow.hono().authorizeMiddleware(["content:read", "content:write"]),
  // Add OpenAPI documentation for this route, including the security requirements and response schema
  describeRoute({
    security: [
      deviceAuthorizationFlow.toOpenAPIPathItem(["content:read", "content:write"]),
    ],
    responses: {
      200: {
        description: "Successful response",
        content: {
          "application/json": {
            schema: resolver(responseSchema),
          },
        },
      },
    },
  }),
  arktypeValidator("json", schema),
  (c) => {
    const username = c.var.credentials?.user?.username;
    const data = c.req.valid("json");
    return c.json({
      success: true,
      message: `${data.name} is ${data.age}`,
      username,
      me: c.get("credentials"), // this will contain the credentials set by the authentication middleware
    });
  },
);

app.post(deviceAuthorizationFlow.getAuthorizationEndpoint(), async (c) => {
  try {
    const url = new URL(c.req.url);
    const forwardedProto = c.req.header("x-forwarded-proto");
    const forwardedHost = c.req.header("x-forwarded-host");
    const origin = forwardedProto && forwardedHost
      ? `${forwardedProto}://${forwardedHost}`
      : url.origin;

    // Here you would typically validate the user's credentials and then proceed with the authorization process
    const result = await deviceAuthorizationFlow.hono().processAuthorization(c);

    if (result.type === "error") {
      // for security reasons, it is recommended to return a generic error message in production instead of the specific error message
      const error = result.error;
      console.log("Authorization endpoint error:", { error: error.name, message: error.message });

      // If the error is not redirectable, render an error message
      return c.json({ error: error.errorCode, error_description: error.message }, 400);
    }

    const { _context, deviceCode, userCode, verificationEndpoint, verificationEndpointComplete } =
      result.deviceCodeResponse;
    console.log("Authorization successful:", {
      deviceCode,
      userCode,
      verificationEndpoint,
      verificationEndpointComplete,
    });

    return c.json({
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: `${origin}${verificationEndpoint}`,
      verification_uri_complete: `${origin}${verificationEndpointComplete}`,
      expires_in: 300,
      interval: 5,
    });
  } catch (error) {
    // unexpected errors should be logged and a generic error message should be returned to the user
    console.log("Unexpected error at authorization endpoint:", {
      error: error instanceof Error ? { name: error.name, message: error.message } : error,
    });
    return c.json(
      { error: "server_error", error_description: "An unexpected error occurred" },
      500,
    );
  }
});

app.get(
  deviceAuthorizationFlow.getVerificationEndpoint(),
  async (c) => {
    // In a real implementation, you would render a page where the user can enter their user code to verify the device authorization request.
    const userCode = c.req.query("user_code");
    if (userCode) {
      const result = await deviceAuthorizationFlow.verifyUserCode(userCode);
      if (result.success) {
        // In a real implementation, you would authenticate the user here,
        // and if authentication is successful, generate an authorization code,
        // and redirect the user to the redirect_uri with the code and state as query parameters.
        console.log("User code verification successful:", {
          userCode,
          deviceCode: result.deviceCode,
        });

        return c.json({
          message: "User code verified successfully. You can now close this page.",
          // In a real implementation, you would not include the following metadata in the response, but it is included here for demonstration purposes.
          metadata: {
            // You can include any additional metadata here that you want
            // to be available in the grant context for generating the access token after the user code is verified
            exampleMetadata: "exampleValue",
          },
        });
      }
    }
    return c.html(
      `<html><body><h1>Device Authorization</h1><p>Please enter your user code to verify your device:</p><form method="POST"><input type="text" name="user_code" /><button type="submit">Verify</button></form></body></html>`,
    );
  },
);

app.post(
  deviceAuthorizationFlow.getVerificationEndpoint(),
  async (c) => {
    // In a real implementation, you would render a page where the user can enter their user code to verify the device authorization request.
    const userCode = (await c.req.formData()).get("user_code");
    if (userCode && typeof userCode === "string") {
      const result = await deviceAuthorizationFlow.verifyUserCode(userCode);
      if (result.success) {
        // In a real implementation, you would authenticate the user here,
        // and if authentication is successful, generate an authorization code,
        // and redirect the user to the redirect_uri with the code and state as query parameters.
        console.log("User code verification successful:", {
          userCode,
          deviceCode: result.deviceCode,
        });

        return c.json({
          message: "User code verified successfully. You can now close this page.",
          // In a real implementation, you would not include the following metadata in the response, but it is included here for demonstration purposes.
          metadata: {
            // You can include any additional metadata here that you want
            // to be available in the grant context for generating the access token after the user code is verified
            exampleMetadata: "exampleValue",
          },
        });
      }
    }
    return c.html(
      `<html><body><h1>Device Authorization</h1><p>Please enter your user code to verify your device:</p><form method="POST"><input type="text" name="user_code" /><button type="submit">Verify</button></form></body></html>`,
    );
  },
);

app.post(
  deviceAuthorizationFlow.getTokenEndpoint(),
  async (c) => {
    console.log("Token endpoint called with body");
    //const result = await clientCredentialsFlow.hono().token(c);
    const result = await deviceAuthorizationFlow.hono().token(c);
    if (result.success) {
      return c.json(result.tokenResponse);
    } else {
      // for security reasons, it is recommended to return a generic error message in production instead of the specific error message
      const error = result.error;
      if (error instanceof UnsupportedGrantTypeError || error instanceof UnauthorizedClientError) {
        return c.json(
          { error: result.error.errorCode, errorDescription: result.error.message },
          400,
        );
      } else {
        console.log("Token endpoint error:", { error: error.name, message: error.message });
        return c.json({ error: "invalid_request" }, 400);
      }
    }
  },
);

app.get(
  "/openapi.json",
  openAPIRouteHandler(app, {
    documentation: {
      info: {
        title: "Astre Hono Device Authorization API",
        version: "1.0.0",
        description: "API for device authorization flow",
      },
      components: {
        securitySchemes: {
          //...deviceAuthorizationFlow.toOpenAPISecurityScheme(),
        },
      },
    },
  }),
);

app.get("/docs/ui", swaggerUI({ url: "/openapi.json" }));
// Serve the oauth2 redirect handler
app.get("/docs/oauth2-redirect.html", oauth2Redirect);

app.get("/health", (c) => c.text("OK"));

Deno.serve({ port: 3000 }, app.fetch);
