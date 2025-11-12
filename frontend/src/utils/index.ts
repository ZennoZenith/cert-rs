import { UnknowError } from "$lib/error.js";
import { Err, Ok, type Result } from "$lib/superposition.js";

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function catchError<T>(
  promise: Promise<T>,
): Promise<Result<T, UnknowError>> {
  try {
    const data = await promise;
    return Ok(data);
  } catch (error) {
    return Err(new UnknowError(error));
  }
}

// Disabled because of any type
// eslint-disable-next-line
// biome-ignore lint/suspicious/noExplicitAny: no explanation
export function catchErrorSync<TArgs extends any[], TReturn>(
  fn: (...args: TArgs) => TReturn,
  ...args: TArgs
): Result<TReturn, UnknowError> {
  try {
    const data = fn(...args);
    return Ok(data);
  } catch (error) {
    return Err(new UnknowError(error));
  }
}
