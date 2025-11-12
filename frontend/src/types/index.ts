import type { POSSIBLE_HTTP_CODE } from "$utils/http-codes.js";

export type Prettify<T> = {
  [K in keyof T]: T[K];
} & {};

export type LightDark = "light" | "dark";
export type Theme = "cupcake" | "forest";

export type ToastType = "INFO" | "SUCCESS" | "WARNING" | "ERROR";
export type LogLevelType = "DEBUG" | "INFO" | "WARN" | "ERROR" | "CRITICAL";
export type Hover = "pause" | "pause-all" | null;

export type InternalApiError = {
  httpCode: POSSIBLE_HTTP_CODE;
  errorCode: number;
  title: string;
  error: string;
  href: string;
};

export type DropDownListItem<
  T extends Record<string, unknown> = { nothing: "" },
> = {
  key: string;
  text: string;
  dataText: string;
  disabled?: boolean;
  selected: boolean;
  extra: T;
};

export type SubscribeAction = "CREATE" | "UPDATE" | "DELETE";

export interface Taged {
  readonly _tag: string;
}

export interface ValueTaged extends Taged {
  readonly value: unknown;
}
