/**
 * UI-009-PRE: Accessible theme selector.
 * Themes are appearance-only. Firewall data never enters storage.
 */
import { useEffect, useState, type ChangeEvent } from "react";

type ThemeName = "midnight" | "cyber" | "light";

const STORAGE_KEY = "firewall-analyzer-ui-theme";

const LABELS: Record<ThemeName, string> = {
  midnight: "Midnight",
  cyber: "Cyber Blue",
  light: "Light",
};

function isThemeName(value: string | null): value is ThemeName {
  return value === "midnight" || value === "cyber" || value === "light";
}

function readInitialTheme(): ThemeName {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (isThemeName(saved)) return saved;
  } catch {
    // The selector still works in browsers that block local storage.
  }
  return "midnight";
}

export default function ThemeSwitcher() {
  const [theme, setTheme] = useState<ThemeName>(readInitialTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-fa-theme", theme);
    document.documentElement.style.colorScheme = theme === "light" ? "light" : "dark";

    try {
      window.localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // Saving a preference is optional; never interrupt the UI.
    }
  }, [theme]);

  function handleChange(event: ChangeEvent<HTMLSelectElement>) {
    const selected = event.target.value;
    if (isThemeName(selected)) setTheme(selected);
  }

  return (
    <div className="fa-theme-picker">
      <label htmlFor="fa-theme-select" className="fa-theme-label">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="9" />
          <circle cx="8" cy="9" r="1" />
          <circle cx="15.5" cy="8.5" r="1" />
          <circle cx="16.5" cy="15" r="1" />
          <path d="M12 21c-2 0-2-2.7-.5-3.8.9-.7 1.7-.5 2.8-.3 1.5.3 3-.6 2.9-2.1" />
        </svg>
        <span>Theme</span>
      </label>
      <span className={`fa-theme-swatch fa-theme-swatch-${theme}`} aria-hidden="true" />
      <select
        id="fa-theme-select"
        value={theme}
        onChange={handleChange}
        className="fa-theme-select"
        aria-label="Application color theme"
        title={`Current theme: ${LABELS[theme]}`}
      >
        <option value="midnight">Midnight</option>
        <option value="cyber">Cyber Blue</option>
        <option value="light">Light</option>
      </select>
    </div>
  );
}
