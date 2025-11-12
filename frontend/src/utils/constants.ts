import type { Hover, LightDark, LogLevelType, Theme } from "$types/index.js";

export const LOG_LEVEL: LogLevelType = "DEBUG";
export const DEFAULT_TOAST_DURATION = 5000; // in milliseconds
export const DEFAULT_TOAST_CLOSE_DURATION = 500; // in milliseconds
export const DEFAULT_TOAST_HOVER: Hover = "pause";
export const DEFAULT_LIGHT_DARK: LightDark = "light";
// export const DEFAULT_THEME: Theme = "cupcake"; // ^DEFAULT_THEME depends on DEFAULT_LIGHT_DARK
export const DARK_THEME: Theme = "forest";
export const LIGHT_THEME: Theme = "cupcake";
