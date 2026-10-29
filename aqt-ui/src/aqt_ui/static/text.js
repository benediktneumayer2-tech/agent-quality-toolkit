// Text written by agents or third parties may hide characters: bidi overrides and isolates,
// zero-width and other format characters, control characters, line and paragraph separators.
// vis() shows each of them as <U+XXXX> (as aqt-quarantine's visible() does), so what the page
// shows reads the way it is stored. Newline and tab stay as they are.
const HIDDEN = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

export function vis(text) {
  return String(text).replace(HIDDEN, (ch) => (ch === "\n" || ch === "\t" ? ch
    : `<U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}>`));
}
