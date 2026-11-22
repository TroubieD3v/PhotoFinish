import { useCallback, useEffect, useState } from "react";

/** An explicit theme, or "system" to follow prefers-color-scheme. */
export type ThemeChoice = "dark" | "light" | "system";
/** The theme in effect. */
export type Theme = "dark" | "light";

const KEY = "photofinish-theme";

function storedChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === "dark" || v === "light" ? v : "system";
  } catch {
    return "system";
  }
}

function systemTheme(): Theme {
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function apply(choice: ThemeChoice) {
  const root = document.documentElement;
  if (choice === "system") delete root.dataset.theme;
  else root.dataset.theme = choice;
}

/** Applied before React renders so that the first paint has the right colors. */
export function initTheme(): void {
  apply(storedChoice());
}

/**
 * Returns the theme in effect and a toggle. Without an explicit choice the
 * theme follows the system (graphite dark when it states no preference);
 * the toggle stores an explicit choice in localStorage.
 */
export function useTheme(): [Theme, () => void] {
  const [choice, setChoice] = useState<ThemeChoice>(storedChoice);
  const [system, setSystem] = useState<Theme>(systemTheme);

  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: light)");
    if (!mq) return;
    const on = () => setSystem(mq.matches ? "light" : "dark");
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);

  useEffect(() => {
    apply(choice);
    try {
      if (choice === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, choice);
    } catch {
      /* storage unavailable: the choice holds for this page only */
    }
  }, [choice]);

  const theme = choice === "system" ? system : choice;
  const toggle = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setChoice(next === system ? "system" : next);
  }, [theme, system]);
  return [theme, toggle];
}
