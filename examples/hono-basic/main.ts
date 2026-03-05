import { Hono } from "hono";
import { type } from "arktype";

import {
  describeRoute,
  openAPIRouteHandler,
  resolver,
  validator as arktypeValidator,
} from "hono-openapi";
import { swaggerUI } from "@hono/swagger-ui";

import {
  UnauthorizedClientError,
  UnsupportedGrantTypeError,
} from "@saurbit/oauth2-server";

import { clientCredentialsFlow } from "./impl/client_credentials.ts";
import { authorizationCodeFlow, HtmlFormContent, HTTPRateLimitException } from "./impl/authorization_code.ts";

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

app.get('/authorize', async (c) => {
  const result = await authorizationCodeFlow.handleAuthorizationEndpointFromHono(c);
  if (result.success) {
    return c.html(HtmlFormContent({ usernameField: "username", passwordField: "password" }));
  } else {
    const error = result.error;
    console.log("Authorization endpoint error:", { error: error.name, message: error.message });
    return c.json({ error: "invalid_request" }, 400);
  }
});

app.post('/authorize',
  async (c) => {
    try {
      const result = await authorizationCodeFlow.processAuthorizationFromHono(c);
      if (result.success) {
        const { user } = result.authorizationCodeResponse
        // Here you would typically validate the user's credentials and then proceed with the authorization process
        // For this example, we'll just log the form data and return a success message
        return c.json({
          message: `User ${user.username} authorized successfully!`,
        });
      } else {
        const error = result.error;
        console.log("Authorization endpoint error:", { error: error.name, message: error.message });
        return c.html(HtmlFormContent({ usernameField: "username", passwordField: "password", errorMessage: error.message }), 400);
      }
    } catch(error) {
      if (error instanceof HTTPRateLimitException) {
        return c.html(HtmlFormContent({ usernameField: "username", passwordField: "password", errorMessage: error.message }), 429);
      }
      console.log("Unexpected error at authorization endpoint:", { error: error instanceof Error ? { name: error.name, message: error.message } : error });
      return c.html(HtmlFormContent({ usernameField: "username", passwordField: "password", errorMessage: "An unexpected error occurred. Please try again later." }), 500);
    }
  });

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
  clientCredentialsFlow.authorizeMiddleware(["content:read", "content:write"]),
  // Add OpenAPI documentation for this route, including the security requirements and response schema
  describeRoute({
    security: [
      clientCredentialsFlow.toOpenAPIPathItem(["content:read", "content:write"]),
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

app.post(
  "/token",
  async (c) => {
    const result = await clientCredentialsFlow.tokenFromHono(c);
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
        title: "Hono",
        version: "1.0.0",
        description: "API for greeting users",
      },
      components: {
        securitySchemes: {
          ...authorizationCodeFlow.toOpenAPISecurityScheme(),
          ...clientCredentialsFlow.toOpenAPISecurityScheme(),
        },
      },
    },
  }),
);

app.get("/ui", swaggerUI({ url: "/openapi.json" }));

app.get("/health", (c) => c.text("OK"));

Deno.serve({ port: 3000 }, app.fetch);
