import { WebComponentRegistery } from "$lib/components.js";
import { TOAST_TYPES, Toaster } from "$lib/toaster.js";
import type { ToastType } from "$types/index.js";
import { defaultSetup } from "$utils/defaultSetup.js";
import { exhaustiveMatchingGuard } from "$utils/helpers.js";

class ToastTest extends HTMLElement {
  connectedCallback() {
    const elements = this.querySelectorAll("[data-emmit-toast-type]");
    for (const element of elements) {
      const toastType = element.getAttribute("data-emmit-toast-type");
      if (toastType === null) continue;
      if (!TOAST_TYPES.includes(toastType as ToastType)) continue;
      element.addEventListener("click", () =>
        showToast(toastType as ToastType),
      );
    }
  }
}

function showToast(toastType: ToastType) {
  const toaster = Toaster.getInstance();
  switch (toastType) {
    case "INFO":
      toaster.info("Info Message", "Info title", 0);
      break;
    case "SUCCESS":
      toaster.success("Success Message", "Success title");
      break;
    case "WARNING":
      toaster.warning("Warning Message", "Warning title");
      break;
    case "ERROR":
      toaster.error("Error Message", "Error title");
      break;
    default:
      exhaustiveMatchingGuard(toastType);
  }
}

function setup() {
  defaultSetup();
  WebComponentRegistery.register("toast-test", ToastTest);
}

setup();
