// CodeMirror 6 setup for scenario YAML. The theme reads the palette from CSS
// variables, so one theme serves the dark and the light variant.

import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { yaml } from "@codemirror/lang-yaml";
import { bracketMatching, HighlightStyle, indentOnInput, indentUnit, syntaxHighlighting } from "@codemirror/language";
import { lintGutter, setDiagnostics, type Diagnostic } from "@codemirror/lint";
import { EditorState, type Extension } from "@codemirror/state";
import {
  drawSelection,
  EditorView,
  highlightActiveLine,
  highlightActiveLineGutter,
  highlightSpecialChars,
  keymap,
  lineNumbers,
} from "@codemirror/view";
import { tags as t } from "@lezer/highlight";
import type { Problem } from "../types";

const theme = EditorView.theme({
  "&": {
    height: "100%",
    color: "var(--ink)",
    backgroundColor: "var(--editor-bg)",
    fontSize: "12.5px",
  },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.6" },
  ".cm-content": { caretColor: "var(--ink)", padding: "6px 0" },
  ".cm-cursor, .cm-dropCursor": { borderLeftColor: "var(--ink)", borderLeftWidth: "1.5px" },
  "&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection":
    { backgroundColor: "var(--selection)" },
  ".cm-activeLine": { backgroundColor: "var(--active-line)" },
  ".cm-gutters": {
    backgroundColor: "var(--editor-gutter)",
    color: "var(--muted)",
    borderRight: "1px solid var(--line)",
  },
  ".cm-activeLineGutter": { backgroundColor: "var(--active-line)", color: "var(--ink)" },
  ".cm-lineNumbers .cm-gutterElement": { padding: "0 10px 0 12px", minWidth: "36px" },
  ".cm-matchingBracket, &.cm-focused .cm-matchingBracket": {
    backgroundColor: "transparent",
    outline: "1px solid var(--muted)",
    borderRadius: "2px",
  },
  ".cm-lintRange-error": {
    backgroundImage: "none",
    textDecoration: "underline wavy var(--bad)",
    textDecorationSkipInk: "none",
    textUnderlineOffset: "3px",
  },
  ".cm-lintRange-warning": {
    backgroundImage: "none",
    textDecoration: "underline wavy var(--warn)",
    textUnderlineOffset: "3px",
  },
  ".cm-gutter-lint": { width: "14px" },
  ".cm-gutter-lint .cm-gutterElement": { padding: "0 2px" },
  ".cm-lint-marker": { width: "10px", height: "10px", marginTop: "5px" },
  ".cm-lint-marker-error": {
    content: "none",
    backgroundColor: "var(--bad)",
    borderRadius: "2px",
  },
  ".cm-tooltip": {
    backgroundColor: "var(--surface)",
    color: "var(--ink)",
    border: "1px solid var(--line)",
    borderRadius: "3px",
    boxShadow: "var(--menu-shadow)",
  },
  ".cm-tooltip-lint": { fontFamily: "var(--sans)", fontSize: "12px" },
  ".cm-diagnostic": { padding: "4px 8px", borderLeft: "3px solid var(--bad)" },
  ".cm-diagnostic-error": { borderLeftColor: "var(--bad)" },
  ".cm-panels": { backgroundColor: "var(--panel)", color: "var(--ink)" },
});

const highlight = HighlightStyle.define([
  { tag: [t.propertyName, t.definition(t.propertyName)], color: "var(--syn-key)" },
  { tag: [t.string, t.special(t.string)], color: "var(--syn-string)" },
  { tag: [t.number, t.bool, t.null, t.atom], color: "var(--syn-number)" },
  { tag: [t.comment, t.lineComment, t.blockComment], color: "var(--syn-comment)", fontStyle: "italic" },
  { tag: [t.keyword, t.typeName, t.labelName, t.meta], color: "var(--syn-meta)" },
  { tag: [t.punctuation, t.separator, t.squareBracket, t.brace, t.operator], color: "var(--syn-punct)" },
  { tag: t.content, color: "var(--ink)" },
]);

/** Options of createEditor. */
export interface EditorOptions {
  parent: HTMLElement;
  doc: string;
  readOnly?: boolean;
  label: string;
  onChange?: (doc: string) => void;
}

/** Creates a YAML editor with line numbers, history, lint gutter and the palette theme. */
export function createEditor(o: EditorOptions): EditorView {
  const extensions: Extension[] = [
    lineNumbers(),
    highlightActiveLineGutter(),
    highlightSpecialChars(),
    history(),
    drawSelection(),
    indentOnInput(),
    bracketMatching(),
    highlightActiveLine(),
    indentUnit.of("  "),
    EditorState.tabSize.of(2),
    keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
    yaml(),
    syntaxHighlighting(highlight),
    lintGutter(),
    theme,
    EditorView.contentAttributes.of({ "aria-label": o.label, spellcheck: "false", autocorrect: "off", autocapitalize: "off" }),
    EditorView.updateListener.of((u) => {
      if (u.docChanged) o.onChange?.(u.state.doc.toString());
    }),
  ];
  if (o.readOnly) extensions.push(EditorState.readOnly.of(true), EditorView.editable.of(false), EditorView.lineWrapping);
  return new EditorView({ parent: o.parent, state: EditorState.create({ doc: o.doc, extensions }) });
}

/** Replaces the whole document (used when a file is loaded). */
export function replaceDoc(view: EditorView, doc: string): void {
  if (view.state.doc.toString() === doc) return;
  view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: doc } });
}

/** Shows validation problems as lint markers; problems without a line are left to the problems list. */
export function showProblems(view: EditorView, problems: Problem[]): void {
  const doc = view.state.doc;
  const diags: Diagnostic[] = [];
  for (const p of problems) {
    if (p.line < 1 || p.line > doc.lines) continue;
    const line = doc.line(p.line);
    let from = line.from;
    if (p.column > 0) from = Math.min(line.to, line.from + p.column - 1);
    else {
      const indent = /^\s*/.exec(line.text)?.[0].length ?? 0;
      from = line.from + indent;
    }
    const to = line.to > from ? line.to : Math.min(doc.length, from + 1);
    diags.push({ from, to, severity: "error", message: p.field ? `${p.field}: ${p.message}` : p.message, source: "photofinish" });
  }
  view.dispatch(setDiagnostics(view.state, diags));
}

/** Moves the cursor to a 1-based line and column and focuses the editor. */
export function goTo(view: EditorView, lineNo: number, column = 0): void {
  const doc = view.state.doc;
  const line = doc.line(Math.min(Math.max(1, lineNo), doc.lines));
  const pos = Math.min(line.to, line.from + Math.max(0, column - 1));
  view.dispatch({ selection: { anchor: pos }, effects: EditorView.scrollIntoView(pos, { y: "center" }) });
  view.focus();
}
