export type AuthClientConfig = {
  apiBaseUrl: string;
};

export function createAuthClient(config: AuthClientConfig) {
  return {
    config,
  };
}

