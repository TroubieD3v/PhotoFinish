import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Check, Copy, TriangleAlert, X } from "lucide-react";
import type { Tone } from "../report";

/** A small colored label: verdicts, statuses, term states. */
export function Lozenge({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`loz ${tone}`} title={title}>
      {children}
    </span>
  );
}

/** An inline error message. */
export function ErrorNote({ children, onDismiss }: { children: ReactNode; onDismiss?: () => void }) {
  return (
    <div className="note-error" role="alert">
      <TriangleAlert size={14} aria-hidden="true" />
      <div className="note-body">{children}</div>
      {onDismiss && (
        <button type="button" className="icon-btn small" onClick={onDismiss} aria-label="Dismiss">
          <X size={14} />
        </button>
      )}
    </div>
  );
}

/** Text that copies itself to the clipboard. */
export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const timer = useRef<number>(0);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Fallback for browsers that refuse the async clipboard.
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    setDone(true);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setDone(false), 1500);
  };
  return (
    <button type="button" className="btn small ghost" onClick={() => void copy()} aria-label={done ? "Copied" : label}>
      {done ? <Check size={13} aria-hidden="true" /> : <Copy size={13} aria-hidden="true" />}
      {done ? "Copied" : label}
    </button>
  );
}

/** A labelled checkbox drawn as a switch. */
export function Toggle({
  checked,
  onChange,
  label,
  hint,
  disabled,
  testId,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  hint?: string;
  disabled?: boolean;
  testId?: string;
}) {
  const id = useId();
  return (
    <div className="toggle-row">
      <input
        id={id}
        type="checkbox"
        className="toggle"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        data-testid={testId}
        aria-describedby={hint ? `${id}-hint` : undefined}
      />
      <label htmlFor={id}>{label}</label>
      {hint && (
        <span id={`${id}-hint`} className="hint">
          {hint}
        </span>
      )}
    </div>
  );
}

/** A centered message for empty lists and loading states. */
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <h3>{title}</h3>
      {children}
    </div>
  );
}

/** A modal dialog with focus kept inside until it closes. */
export function Dialog({
  title,
  children,
  actions,
  onClose,
}: {
  title: string;
  children: ReactNode;
  actions: ReactNode;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("[data-autofocus], button");
    first?.focus();
    return () => prev?.focus?.();
  }, []);
  const onKey = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !ref.current) return;
      const items = ref.current.querySelectorAll<HTMLElement>("button, input, select, textarea, a[href]");
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    },
    [onClose],
  );
  return (
    <div className="scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref} onKeyDown={onKey}>
        <h2 id={titleId}>{title}</h2>
        <div className="dialog-body">{children}</div>
        <div className="dialog-actions">{actions}</div>
      </div>
    </div>
  );
}

/** A page header: title, optional detail line and actions on the right. */
export function PageHead({ title, detail, children }: { title: ReactNode; detail?: ReactNode; children?: ReactNode }) {
  return (
    <header className="page-head">
      <div className="page-title">
        <h1>{title}</h1>
        {detail && <span className="page-detail">{detail}</span>}
      </div>
      {children && <div className="page-actions">{children}</div>}
    </header>
  );
}

/** Message of an unknown error. */
export function errorText(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
