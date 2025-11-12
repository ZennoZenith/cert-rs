import { setupTheme } from "$lib/theme.js";
import { setupToaster } from "$lib/toaster.js";

export function defaultSetup() {
  setupToaster();
  setupTheme();
}
