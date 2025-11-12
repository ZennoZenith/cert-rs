"use strict";
const DARK_THEME = "forest";
const LIGHT_THEME = "cupcake";
function loadThemeFromLocalStorage() {
    const theme = localStorage.getItem("theme");
    if (theme === null) {
        return undefined;
    }
    if (theme.toLowerCase() === "dark") {
        return "dark";
    }
    else if (theme.toLowerCase() === "light") {
        return "light";
    }
    // If theme is neither "dark" nor "light"
    localStorage.removeItem("theme");
    return undefined;
}
function detectColorScheme() {
    const DARK = "(prefers-color-scheme: dark)";
    // const LIGHT = "(prefers-color-scheme: light)";
    if (!window.matchMedia) {
        return "light";
    }
    if (window.matchMedia(DARK).matches) {
        return "dark";
    }
    return "light";
}
function setTheme(darkLight, store = false) {
    if (darkLight === "light") {
        document.documentElement.dataset.theme = LIGHT_THEME;
    }
    else {
        document.documentElement.dataset.theme = DARK_THEME;
    }
    if (store) {
        localStorage.setItem("theme", darkLight);
    }
    window.dispatchEvent(new CustomEvent("themechange", {
        detail: {
            value: darkLight,
        },
    }));
    return darkLight;
}
const theme = loadThemeFromLocalStorage();
if (theme === undefined) {
    setTheme(detectColorScheme());
}
else {
    setTheme(theme);
}
