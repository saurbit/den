declare module "@saurbit/oauth2" {
  interface UserCredentials {
    username: string;
    level?: number;
  }
  interface AppCredentials {
    name: string;
  }
}

export {};
