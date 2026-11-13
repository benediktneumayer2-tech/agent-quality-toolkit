// Copies the aqt-ui pages into frontend/ for the app window, in the layout `aqt ui` serves them: index.html at
// the root and the files under static/ (the page loads /static/app.js and /static/app.css). The one source is
// aqt-ui/src/aqt_ui/static; frontend/ is generated and git-ignored. Unknown paths (/case/..., /change/...) get
// index.html from Tauri's asset fallback, so the page's pathname routing works in the app as in the browser.
//
// The app's Content-Security-Policy allows no inline code, so this refuses inline scripts, styles and event
// handlers in the copied HTML instead of shipping a page that would not run.
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const desktop = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(desktop, "..", "aqt-ui", "src", "aqt_ui", "static");
const target = join(desktop, "frontend");

const INLINE = [
  [/<script(?![^>]*\bsrc=)[^>]*>/i, "an inline <script>"],
  [/<style\b/i, "a <style> element"],
  [/\sstyle\s*=/i, "a style attribute"],
  [/\son[a-z]+\s*=/i, "an inline event handler"],
  [/javascript:/i, "a javascript: address"],
];
for (const name of readdirSync(source).filter((n) => n.endsWith(".html"))) {
  const html = readFileSync(join(source, name), "utf8");
  for (const [pattern, what] of INLINE) {
    if (pattern.test(html)) {
      console.error(`sync-frontend: ${name} has ${what}, which the app's CSP blocks`);
      process.exit(1);
    }
  }
}

rmSync(target, { recursive: true, force: true });
mkdirSync(target, { recursive: true });
cpSync(source, join(target, "static"), { recursive: true });
cpSync(join(source, "index.html"), join(target, "index.html"));
console.log(`sync-frontend: ${source} -> ${target}`);
