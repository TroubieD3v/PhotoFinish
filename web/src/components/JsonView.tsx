import { useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

/** Objects and arrays deeper than this start collapsed. */
const OPEN_DEPTH = 3;

function Scalar({ value }: { value: unknown }) {
  if (value === null) return <span className="j-null">null</span>;
  switch (typeof value) {
    case "string":
      return <span className="j-str">{JSON.stringify(value)}</span>;
    case "number":
      return <span className="j-num">{String(value)}</span>;
    case "boolean":
      return <span className="j-bool">{String(value)}</span>;
    default:
      return <span>{String(value)}</span>;
  }
}

function Node({ name, value, depth, last }: { name?: ReactNode; value: unknown; depth: number; last: boolean }) {
  const isArr = Array.isArray(value);
  const isObj = typeof value === "object" && value !== null;
  const [open, setOpen] = useState(depth < OPEN_DEPTH);
  const comma = last ? "" : ",";
  const key = name !== undefined && (
    <>
      {name}
      <span className="j-punct">: </span>
    </>
  );
  if (!isObj) {
    return (
      <div className="j-line" style={{ paddingLeft: depth * 14 }}>
        {key}
        <Scalar value={value} />
        {comma}
      </div>
    );
  }
  const entries: [string, unknown][] = isArr ? (value as unknown[]).map((v, i) => [String(i), v]) : Object.entries(value as object);
  const [o, c] = isArr ? ["[", "]"] : ["{", "}"];
  if (entries.length === 0) {
    return (
      <div className="j-line" style={{ paddingLeft: depth * 14 }}>
        {key}
        <span className="j-punct">
          {o}
          {c}
        </span>
        {comma}
      </div>
    );
  }
  const summary = isArr ? `${entries.length} items` : `${entries.length} keys`;
  return (
    <>
      <div className="j-line" style={{ paddingLeft: depth * 14 }}>
        <button
          type="button"
          className="j-toggle"
          aria-expanded={open}
          aria-label={open ? "Collapse" : "Expand"}
          onClick={() => setOpen(!open)}
        >
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </button>
        {key}
        <span className="j-punct">{o}</span>
        {!open && (
          <>
            <button type="button" className="j-more" onClick={() => setOpen(true)}>
              {summary}
            </button>
            <span className="j-punct">{c}</span>
            {comma}
          </>
        )}
      </div>
      {open && (
        <>
          {entries.map(([k, v], i) => (
            <Node
              key={k}
              name={isArr ? undefined : <span className="j-key">{JSON.stringify(k)}</span>}
              value={v}
              depth={depth + 1}
              last={i === entries.length - 1}
            />
          ))}
          <div className="j-line" style={{ paddingLeft: depth * 14 }}>
            <span className="j-punct">{c}</span>
            {comma}
          </div>
        </>
      )}
    </>
  );
}

/** A JSON value pretty-printed with collapsible objects and arrays. */
export function JsonView({ value }: { value: unknown }) {
  return (
    <div className="json" data-testid="json-view">
      <Node value={value} depth={0} last />
    </div>
  );
}
