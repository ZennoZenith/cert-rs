import type { LightDark } from "$types/index.js";
import {
  DARK_THEME,
  DEFAULT_LIGHT_DARK,
  LIGHT_THEME,
} from "$utils/constants.js";
import { WebComponentRegistery } from "./components.js";

function detectColorScheme(): LightDark {
  const DARK = "(prefers-color-scheme: dark)";
  // const LIGHT = "(prefers-color-scheme: light)";

  if (!window.matchMedia) {
    return DEFAULT_LIGHT_DARK;
  }

  if (window.matchMedia(DARK).matches) {
    return "dark";
  }

  return "light";
}

function loadThemeFromLocalStorage(): LightDark | undefined {
  const theme = localStorage.getItem("theme");
  if (theme === null) {
    return undefined;
  }

  if (theme.toLowerCase() === "dark") {
    return "dark";
  } else if (theme.toLowerCase() === "light") {
    return "light";
  }

  // If theme is neither "dark" nor "light"
  localStorage.removeItem("theme");

  return undefined;
}

function setTheme(darkLight: LightDark, store: boolean = false): LightDark {
  if (darkLight === "light") {
    document.documentElement.dataset.theme = LIGHT_THEME;
  } else {
    document.documentElement.dataset.theme = DARK_THEME;
  }

  if (store) {
    localStorage.setItem("theme", darkLight);
  }

  window.dispatchEvent(
    new CustomEvent("themechange", {
      detail: {
        value: darkLight,
      },
    }),
  );

  return darkLight;
}

export class ThemeToggle extends HTMLElement {
  private theme: LightDark;
  constructor() {
    super();
    const theme = loadThemeFromLocalStorage();

    if (theme === undefined) {
      this.theme = setTheme(detectColorScheme());
    } else {
      this.theme = setTheme(theme);
    }
  }

  connectedCallback() {
    const element = this.querySelector<HTMLInputElement>(
      "input[data-theme-toggle]",
    );
    if (!element) {
      console.warn("Theme toggle not found");
      return;
    }

    element.checked = this.theme === "dark";
    element.classList.remove("hidden");

    element.addEventListener("change", () => {
      if (element.checked) {
        setTheme("dark", true);
      } else {
        setTheme("light", true);
      }
    });
  }
}

export function setupTheme() {
  WebComponentRegistery.register("theme-toggle", ThemeToggle);
}
