export const NO_CONTENT = 204 as const;
export const BAD_REQUEST = 400 as const;
export const NOT_FOUND = 404 as const;
export const INTERNAL_SERVER_ERROR = 500 as const;
export const possible_http_code = [
  NO_CONTENT,
  BAD_REQUEST,
  INTERNAL_SERVER_ERROR,
] as const;
export type POSSIBLE_HTTP_CODE =
  | (typeof possible_http_code)[number]
  | ({} & number);
