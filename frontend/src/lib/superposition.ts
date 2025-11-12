import type { Taged } from "$types/index.js";

export class Result<T, E extends Taged> {
  #ok?: T;
  #err?: E;

  constructor(ok?: T, err?: E) {
    this.#ok = ok;
    this.#err = err;
  }

  unwrap(errorFn?: (message: string) => void) {
    if (this.#ok === undefined || this.#ok === null) {
      if (errorFn) {
        errorFn("Unwrapping empty result");
      } else {
        throw new Error("Unwrapping empty result", { cause: this.#err });
      }
    }
    return this.#ok as NonNullable<T>;
  }

  unwrapOr(value: NonNullable<T>) {
    if (!this.#ok) {
      return value;
    }
    return this.#ok;
  }

  unwrapElseOr(fn: () => NonNullable<T>) {
    if (!this.#ok) {
      return fn();
    }
    return this.#ok;
  }

  unwrapErr(errorFn?: (message: string) => void) {
    if (this.#err === undefined || this.#err === null) {
      if (errorFn) {
        errorFn("Unwrapping empty error");
      } else {
        throw new Error("Unwrapping empty error", { cause: this.#ok });
      }
    }

    return this.#err as NonNullable<E>;
  }

  isOk() {
    return this.#ok !== undefined && this.#ok !== null;
  }

  isErr() {
    return this.#err !== undefined && this.#err !== null;
  }

  // get ok() {
  //   return this.#ok;
  // }

  // get err() {
  //   return this.#err;
  // }
}

export function Ok<T>(ok: T) {
  return new Result<T, never>(ok);
}

export function Err<E extends Taged>(err: E) {
  return new Result<never, E>(undefined, err);
}

export const isOk = <T, E extends Taged>(
  value: Result<T, E>,
): value is Result<T, never> => value.isOk();

export const isErr = <T, E extends Taged>(
  value: Result<T, E>,
): value is Result<never, E> => value.isErr();
