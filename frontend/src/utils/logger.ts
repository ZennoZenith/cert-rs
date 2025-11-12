import { isErr } from "$lib/superposition.js";
import type { LogLevelType } from "$types/index.js";
import { LOG_LEVEL } from "$utils/constants.js";
import { exhaustiveMatchingGuard, toLogLevel } from "$utils/helpers.js";
import { catchErrorSync } from "$utils/index.js";

type FormatLogOptions = {
  message: unknown;
  logLevel: LogLevelType;
  eventTag?: string;
};

export class Log {
  constructor() {
    throw Error("Log is an static class and cannot be instantiated.");
  }
  private static LogLevelValue = 10;
  private static _logLevel: LogLevelType = LOG_LEVEL;

  static get LogLevel() {
    return Log._logLevel;
  }

  static set LogLevel(value: string) {
    Log._logLevel = toLogLevel(value);
    switch (Log._logLevel) {
      case "DEBUG":
        Log.LogLevelValue = 0;
        break;
      case "INFO":
        Log.LogLevelValue = 5;
        break;
      case "WARN":
        Log.LogLevelValue = 10;
        break;
      case "ERROR":
        Log.LogLevelValue = 15;
        break;
      case "CRITICAL":
        Log.LogLevelValue = 20;
        break;
      default:
        exhaustiveMatchingGuard(Log._logLevel);
    }
  }

  private static FormatDate(date: Date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0"); // Ensure two digits
    const day = String(date.getDate()).padStart(2, "0");
    const hours = String(date.getHours()).padStart(2, "0");
    const minutes = String(date.getMinutes()).padStart(2, "0");
    const seconds = String(date.getSeconds()).padStart(2, "0");
    const miliseconds = String(date.getMilliseconds()).padStart(3, "0");
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${miliseconds}`;
  }

  private static FormatLog(option: FormatLogOptions) {
    const log: string[] = [];
    log.push(Log.FormatDate(new Date()));
    log.push("INFO");
    if (option.eventTag) log.push(`Event: ${option.eventTag}`);

    if (typeof option.message === "string") {
      log.push(`Message: ${option.message}`);
    } else {
      const jsonOrError = catchErrorSync(
        JSON.stringify,
        option.message,
        null,
        2,
      );
      if (isErr(jsonOrError)) {
        log.push(`Message: ${option.message}`);
      } else {
        log.push(`Message: ${jsonOrError.unwrap()}`);
      }
    }

    return log.join(" | ");
  }

  static debug(message: unknown, eventTag?: string) {
    if (Log.LogLevelValue > 0) return;
    console.log(Log.FormatLog({ logLevel: "DEBUG", message, eventTag }));
  }
  static info(message: unknown | Record<string, unknown>, eventTag?: string) {
    if (Log.LogLevelValue > 5) return;
    console.log(Log.FormatLog({ logLevel: "INFO", message, eventTag }));
  }
  static warn(message: unknown, eventTag?: string) {
    if (Log.LogLevelValue > 10) return;
    console.log(Log.FormatLog({ logLevel: "WARN", message, eventTag }));
  }
  static error(message: unknown, eventTag?: string) {
    if (Log.LogLevelValue > 15) return;
    console.log(Log.FormatLog({ logLevel: "ERROR", message, eventTag }));
  }
  static critical(message: unknown, eventTag?: string) {
    if (Log.LogLevelValue > 20) return;
    console.log(Log.FormatLog({ logLevel: "CRITICAL", message, eventTag }));
  }
}

Log.LogLevel = LOG_LEVEL;
