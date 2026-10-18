import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";

export type MenuItem =
  | { kind: "item"; label: string; onSelect?: () => void; disabled?: boolean; hint?: string; swatch?: string }
  | { kind: "separator" }
  | { kind: "submenu"; label: string; items: MenuItem[] };

type Props = { x: number; y: number; items: MenuItem[]; onClose: () => void };

export function ContextMenu({ x, y, items, onClose }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ x, y });

  // Keep the menu inside the viewport.
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    setPos({
      x: Math.min(x, window.innerWidth - r.width - 4),
      y: Math.min(y, window.innerHeight - r.height - 4),
    });
  }, [x, y]);

  useEffect(() => {
    const close = (e: Event) => {
      if (e instanceof KeyboardEvent && e.key !== "Escape") return;
      if (e instanceof MouseEvent && ref.current?.contains(e.target as Node)) return;
      onClose();
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", close);
    window.addEventListener("blur", onClose);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", close);
      window.removeEventListener("blur", onClose);
    };
  }, [onClose]);

  return (
    <div ref={ref} className="menu" style={{ left: pos.x, top: pos.y }} onContextMenu={(e) => e.preventDefault()}>
      <MenuList items={items} onClose={onClose} />
    </div>
  );
}

function MenuList({ items, onClose }: { items: MenuItem[]; onClose: () => void }): ReactNode {
  return items.map((it, i) => {
    if (it.kind === "separator") return <div key={i} className="menu-sep" />;
    if (it.kind === "submenu") {
      return (
        <div key={i} className="menu-item menu-has-sub">
          <span>{it.label}</span>
          <span className="menu-hint">▸</span>
          <div className="menu menu-sub">
            <MenuList items={it.items} onClose={onClose} />
          </div>
        </div>
      );
    }
    return (
      <button
        key={i}
        className="menu-item"
        disabled={it.disabled}
        onClick={() => {
          it.onSelect?.();
          onClose();
        }}
      >
        {it.swatch && <span className={`swatch hl-${it.swatch}`} />}
        <span>{it.label}</span>
        {it.hint && <span className="menu-hint">{it.hint}</span>}
      </button>
    );
  });
}
