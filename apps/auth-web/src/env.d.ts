/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AUTH_API_BASE_URL?: string;
  readonly VITE_AUTH_WEB_BASE_URL?: string;
  readonly VITE_AUTH_ALLOWED_RETURN_ORIGINS?: string;
  readonly VITE_AUTH_DEFAULT_RETURN_TO?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
