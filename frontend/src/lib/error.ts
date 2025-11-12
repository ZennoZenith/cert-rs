import type { InternalApiError, Taged } from "$types/index.js";

const errorType = [
  "UnknownError",
  "UntagedError",
  "FetchError",
  "JsonDeserializeError",
  "ApiError",
  "ApiModelError",
  "ValidationError",
  "CriticalError",
  // "ParseError",
] as const;

export type ErrorType = (typeof errorType)[number] | ({} & string);

export type ErrorObject = Readonly<{
  _tag: ErrorType;
  success: false;
  message: string;
  messages: [string, ...string[]];
  cause: unknown;
  extra: Record<string, unknown>;
}>;

function stringToNumber(value: unknown) {
  const n = Number(value);
  return Number.isNaN(n) ? null : n;
}

function constructApiError(err?: unknown): InternalApiError {
  if (typeof err !== "object" || err === null) {
    return {
      error: "-1",
      errorCode: -1,
      href: "",
      httpCode: 418,
      title: "",
    } satisfies InternalApiError;
  }
  const obj: Partial<InternalApiError> = {};
  if ("error" in err) obj.error = err?.error?.toString();
  if ("errorCode" in err) stringToNumber(err?.errorCode);
  if ("href" in err) err?.href?.toString();
  if ("httpCode" in err) stringToNumber(err?.httpCode);
  if ("title" in err) err?.title?.toString();

  return {
    error: obj.error ?? "-1",
    errorCode: obj.errorCode ?? -1,
    href: obj.href ?? "",
    httpCode: obj.httpCode ?? 418,
    title: obj.title ?? "",
  } satisfies InternalApiError;
}

// const errorSchema = pipe(
//   object(
//     {
//       success: literal(false, "success should be boolean false"),
//       type: union(
//         errorType.map(v => literal(v)),
//         "invalid error type",
//       ),
//       message: string("message should be string"),
//       name: optional(string("name should be string")),
//       cause: optional(unknown()),
//       messages: pipe(
//         array(
//           string("messages should be string"),
//           "messages should be an array of string",
//         ),
//         minLength(1, "messages array should atleast contain one element of string"),
//       ),
//       extra: record(
//         string("extra object key shoud be string"),
//         unknown(),
//         "extra must by of type Record<string, unknown>",
//       ),
//     },
//   ),
// );

class CustomError extends Error implements Taged {
  readonly _tag: ErrorType;
  // readonly messages: [string, ...string[]];
  // extra: Record<string, unknown>;

  constructor(tag: ErrorType, message: string) {
    super(message);
    this._tag = tag;
  }

  // fromError(error: Error, extra?: Record<string, unknown>, messages?: [string, ...string[]]) {
  //   this.cause = error.cause;
  //   this.message = error.message;
  //   this.name = error.name;
  //   this.stack = error.stack;
  //   this.messages = messages ?? [this.message];
  //   this.extra = extra ?? {};
  //   return this;
  // }

  // static parseError(value: unknown) {
  //   const d = safeParse(errorSchema, value);
  //   if (!d.success) {
  //     return new ParseError(undefined, ["Unable to parse error schema"]);
  //   }
  //   const { type, extra, messages, cause, name } = d.output;
  //   const customError = new CustomError(type, extra, messages as [string, ...string[]]);
  //   customError.cause = cause;
  //   customError.name = name ?? "";
  //   return customError;
  // }

  // get error(): ErrorObject {
  //   return {
  //     _tag: this._tag,
  //     success: this.success,
  //     message: this.message,
  //     messages: this.messages,
  //     cause: this.cause,
  //     extra: this.extra,
  //   } as const;
  // }
}

// export class GenericError extends CustomError {
//   constructor(extra?: Record<string, unknown>, messages?: [string, ...string[]]) {
//     super("GenericError", extra, messages ?? ["Generic Error"]);
//   }
// }

export class UnknowError extends CustomError {
  readonly error: Error;
  constructor(error: unknown) {
    let message = "Unknow Message";
    if (
      typeof error === "object" &&
      error !== null &&
      "message" in error &&
      typeof error.message === "string"
    )
      message = error.message;
    super("UnknownError", message);
    if (error instanceof Error) {
      this.error = error;
      return;
    }
    this.error = new Error(message, { cause: error });
  }
}

export class TagedError extends CustomError {
  readonly error: Error;
  constructor(error: Taged) {
    let message = "Unknow Message";
    if (
      typeof error === "object" &&
      error !== null &&
      "message" in error &&
      typeof error.message === "string"
    )
      message = error.message;
    super(error._tag, message);
    if (error instanceof Error) {
      this.error = error;
      return;
    }
    this.error = new Error(message, { cause: error });
  }
}

export class UntagedError extends CustomError {
  readonly error: Error;
  constructor(error: Error) {
    super("UntagedError", error.message);
    this.error = error;
  }
}

export class FetchError extends CustomError {
  readonly error: Error;
  constructor(error: Error) {
    super("FetchError", error.message);
    this.error = error;
  }

  static fromUnknownError(error: UnknowError) {
    return new FetchError(error.error);
  }
}

export class JsonDeserializeError extends CustomError {
  readonly error: Error;
  constructor(error: Error) {
    super("JsonDeserializeError", error.message);
    this.error = error;
  }

  static fromUnknownError(error: UnknowError) {
    return new FetchError(error.error);
  }
}

export class ApiError extends CustomError {
  readonly error: InternalApiError;

  constructor(error: Record<string, unknown>) {
    const apiError = constructApiError(error);
    super("ApiError", apiError.error);
    this.error = apiError;
  }
}

export class ValidationError extends CustomError {
  readonly validationError: Record<string, unknown>;

  constructor(
    validationError: Record<string, unknown>,
    tag: ErrorType = "ValidationError",
    message?: string,
  ) {
    super(tag, message ?? "Validation Error");
    this.validationError = validationError;
  }
}

export class ApiModelError extends CustomError {
  readonly validationError: Record<string, unknown>;

  constructor(extra: Record<string, unknown>, message?: string) {
    super("ApiModelError", message ?? "Api Model Error");
    this.validationError = extra;
  }

  // static fromValidationError(error: ValidationError) {
  //   return new ApiModelError(
  //     error.validationError,
  //     error.message === "Validation Error" ? undefined : error.message,
  //   );
  // }
}
export class CriticalError extends CustomError {
  constructor(message: string) {
    super("CriticalError", message);
  }
}
