import type { Hover, ToastType } from "$types/index.js";
import {
  DEFAULT_TOAST_CLOSE_DURATION,
  DEFAULT_TOAST_DURATION,
  DEFAULT_TOAST_HOVER,
} from "$utils/constants.js";
import { clamp, exhaustiveMatchingGuard, uuidv4 } from "$utils/helpers.js";
import { WebComponentRegistery } from "./components.js";

export const TOAST_TYPES: ToastType[] = [
  "INFO",
  "SUCCESS",
  "WARNING",
  "ERROR",
] as const;

function setIfEmptyTitle(toastType: ToastType, title?: string) {
  let altTitle = "";
  switch (toastType) {
    case "INFO":
      altTitle = "Info";
      break;
    case "SUCCESS":
      altTitle = "Success";
      break;
    case "WARNING":
      altTitle = "Warning";
      break;
    case "ERROR":
      altTitle = "Error";
      break;
    default:
      exhaustiveMatchingGuard(toastType);
  }

  if (!title) return altTitle;
  if (title.trim().length === 0) return altTitle;

  return title;
}

class Toast {
  public readonly id: string;
  public readonly toastType: ToastType;
  public readonly title: string;
  public readonly message: string;
  public readonly durationMs: number;
  public readonly createdAtMs: number;
  public readonly _toastElement: HTMLDivElement;

  private _paused: boolean;
  private lastFrameTime: number;
  private doneDuration: number;
  public readonly progressBarElement: HTMLDivElement;

  constructor(
    options?: Partial<{
      toastType: ToastType;
      title: string;
      message: string;
      durationMs: number;
      paused: boolean;
      doneTime: number;
    }>,
  ) {
    const toastType = options?.toastType ?? "INFO";
    const durationMs = options?.durationMs ?? DEFAULT_TOAST_DURATION;
    const now = Date.now();

    const id = uuidv4();
    this.id = id;
    this.toastType = toastType;
    this.title = setIfEmptyTitle(toastType, options?.title);
    this.message = options?.message ?? "";
    this.durationMs = durationMs < 0 ? 0 : durationMs;
    this.createdAtMs = now;
    this._paused = options?.paused ?? false;

    const maybeTemplate = document.getElementById(
      "toast-template",
    ) as HTMLTemplateElement | null;
    if (!maybeTemplate) {
      throw new Error("toast-template not found");
    }

    const templateContent = maybeTemplate.content.cloneNode(
      true,
    ) as DocumentFragment;
    const templateContentDiv = templateContent.querySelector("div");
    if (!templateContentDiv) {
      throw new Error("toast-template does not have div element");
    }
    this._toastElement = templateContentDiv;
    this.lastFrameTime = performance.now();
    this.doneDuration = 0;

    const maybeProgressBarElement = this._toastElement.querySelector(
      "[data-id='progress']",
    ) as HTMLDivElement | null;
    if (!maybeProgressBarElement) {
      throw new Error("maybeProgressBarElement not found");
    }
    this.progressBarElement = maybeProgressBarElement;

    this.setupRest();
  }

  private setupRest() {
    this.paused = this._paused;

    const titleElement = this._toastElement.querySelector(
      "[data-id='title']",
    ) as HTMLSpanElement | null;
    if (titleElement) {
      titleElement.textContent = this.title;
    }

    this._toastElement
      .querySelector("[data-id='closeButton']")
      ?.addEventListener("click", () => {
        Toaster.getInstance().remove(this.id);
      });

    this._toastElement.addEventListener("mouseenter", () => {
      Toaster.getInstance().pause(this.id);
    });
    this._toastElement.addEventListener("mouseleave", () => {
      Toaster.getInstance().resume(this.id);
    });

    const spanElement = this._toastElement.querySelector(
      "[data-id='dot-separator']",
    ) as HTMLSpanElement | null;
    if (!spanElement) return;

    const svgTextColorElement = this._toastElement.querySelector(
      "[data-id='svg-text-color']",
    ) as HTMLDivElement | null;
    if (!svgTextColorElement) return;

    const messageElement = this._toastElement.querySelector(
      "[data-id='message']",
    ) as HTMLDivElement | null;
    if (!messageElement) return;

    messageElement.textContent = this.message;

    let className = "";
    let svgColorClassName = "";

    switch (this.toastType) {
      case "INFO":
        svgColorClassName = "text-info";
        className = "bg-info text-info-content";
        svgTextColorElement.appendChild(document.createElement("info-svg"));
        break;
      case "SUCCESS":
        svgColorClassName = "text-success";
        className = "bg-success text-success-content";
        svgTextColorElement.appendChild(document.createElement("success-svg"));
        break;
      case "WARNING":
        svgColorClassName = "text-warning";
        className = "bg-warning text-warning-content";
        svgTextColorElement.appendChild(document.createElement("warning-svg"));
        break;
      case "ERROR":
        svgColorClassName = "text-error";
        className = "bg-error text-error-content";
        svgTextColorElement.appendChild(document.createElement("error-svg"));
        break;
      default:
        exhaustiveMatchingGuard(this.toastType);
    }
    spanElement.classList.add(...className.split(" "));
    svgTextColorElement.classList.add(...svgColorClassName.split(" "));

    const frameUpdate = (time: number) => {
      const diff = time - this.lastFrameTime;

      if (this._paused === false) {
        this.doneDuration += diff;
        if (this.durationMs === 0) {
          this.progressBarElement.style.transform = `translateX(-100%)`;
        } else {
          this.progressBarElement.style.transform = `translateX(-${(this.doneDuration / this.durationMs) * 100}%)`;
        }
        if (this.doneDuration > this.durationMs) return;
      }

      this.lastFrameTime = time;
      requestAnimationFrame(frameUpdate);
    };

    requestAnimationFrame(frameUpdate);
  }

  public remove() {
    this._toastElement.classList.remove("toastSlideInRight");
    this._toastElement.classList.add("toastSlideOutRight");

    setTimeout(() => {
      this._toastElement.remove();
    }, DEFAULT_TOAST_CLOSE_DURATION);
  }

  get toastElement() {
    return this._toastElement;
  }

  get paused() {
    return this._paused;
  }

  get done() {
    if (this.durationMs === 0) return 1;
    return clamp(this.doneDuration / this.durationMs, 0, 1);
  }

  set paused(value: boolean) {
    const pauseElement = this._toastElement.querySelector("[data-id='paused']");

    if (pauseElement && value === false) {
      pauseElement.classList.add("hidden");
    } else if (pauseElement) {
      pauseElement.classList.remove("hidden");
    }

    this._paused = value;
  }
}

/*
 * Is a singelton
 */
export class Toaster {
  private static INSTANCE: Toaster;
  private toastContainer: HTMLElement;
  private hover: Hover = DEFAULT_TOAST_HOVER;
  private toastToTimeout = new Map<string, Timer>();

  private toasts: Toast[];
  private toasted: Toast[];

  private constructor() {
    const maybeTemplate = document.getElementById(
      "toast-container-template",
    ) as HTMLTemplateElement | null;
    if (!maybeTemplate) {
      throw new Error("toast-container-template not found");
    }

    const templateContent = maybeTemplate.content.cloneNode(
      true,
    ) as DocumentFragment;
    const templateContentDiv = templateContent.querySelector("div");
    const templateContentStyle = templateContent.querySelector("style");
    if (!templateContentDiv) {
      throw new Error("toast-container-template does not have div element");
    }

    document.body.append(templateContentDiv);
    if (templateContentStyle) document.head.appendChild(templateContentStyle);

    this.toastContainer = templateContentDiv;
    this.toasts = [];
    this.toasted = [];
  }

  public static getInstance(): Toaster {
    if (Toaster.INSTANCE) {
      return Toaster.INSTANCE;
    }
    Toaster.INSTANCE = new Toaster();
    return Toaster.INSTANCE;
  }

  private add(
    toastType: ToastType,
    message: string,
    title?: string,
    durationMs?: number,
  ) {
    const toast = new Toast({
      toastType,
      title,
      message,
      durationMs,
    });
    this.toastContainer.appendChild(toast.toastElement);

    // this.toastContainer.scrollTop = this.toastContainer.scrollHeight;

    this.toasts.push(toast);

    this.toastToTimeout.set(
      toast.id,
      setTimeout(() => {
        if (toast.durationMs === 0) {
          return;
        }
        this.remove(toast.id);
      }, toast.durationMs),
    );
  }

  remove(id: string) {
    const timeout = this.toastToTimeout.get(id);
    if (timeout) {
      clearTimeout(timeout);
      this.toastToTimeout.delete(id);
    }
    const toastIndexToRemove = this.toasts.findIndex((v) => v.id === id);
    if (toastIndexToRemove < 0) return;
    if (this.toasts[toastIndexToRemove] === undefined) return;

    const toast = this.toasts[toastIndexToRemove];
    toast.remove();
    this.toasted.push(toast);
    this.toasts.splice(toastIndexToRemove, 1);
  }

  pause(id: string) {
    if (this.hover === null) return;

    if (this.hover === "pause") {
      const toast = this.toasts.find((v) => v.id === id);
      this._pauseToast(toast);
      return;
    }

    if (this.hover === "pause-all") {
      for (const toast of this.toasts) {
        this._pauseToast(toast);
      }
      return;
    }
  }

  resume(id: string) {
    if (this.hover === null) return;

    if (this.hover === "pause") {
      const toast = this.toasts.find((v) => v.id === id);
      this._resumeToast(toast);
      return;
    }

    if (this.hover === "pause-all") {
      for (const toast of this.toasts) {
        this._resumeToast(toast);
      }
      return;
    }
  }

  private _pauseToast(toast?: Toast) {
    if (!toast) return;
    if (toast.paused === true) return;
    if (toast.durationMs === 0) return;

    const timeout = this.toastToTimeout.get(toast.id);
    if (timeout) {
      clearTimeout(timeout);
      this.toastToTimeout.delete(toast.id);
    }
    toast.paused = true;
  }

  private _resumeToast(toast?: Toast) {
    if (!toast) return;
    if (toast.paused === false) return;
    if (toast.durationMs === 0) return;

    toast.paused = false;

    const remainingMs = (1 - toast.done) * toast.durationMs;
    this.toastToTimeout.set(
      toast.id,
      setTimeout(() => {
        if (remainingMs === 0) {
          return;
        }
        this.remove(toast.id);
      }, remainingMs),
    );
  }

  public info(message: string, title = "", durationMs?: number) {
    this.add("INFO", message, title, durationMs);
  }

  public success(message: string, title = "", durationMs?: number) {
    this.add("SUCCESS", message, title, durationMs);
  }

  public warning(message: string, title = "", durationMs?: number) {
    this.add("WARNING", message, title, durationMs);
  }

  public error(message: string, title = "", durationMs?: number) {
    this.add("ERROR", message, title, durationMs);
  }
}

export function setupToaster() {
  // registerWebComponents
  WebComponentRegistery.register("close-cross-svg");
  WebComponentRegistery.register("info-svg");
  WebComponentRegistery.register("success-svg");
  WebComponentRegistery.register("warning-svg");
  WebComponentRegistery.register("error-svg");
  WebComponentRegistery.register("toast-container-template");
}
