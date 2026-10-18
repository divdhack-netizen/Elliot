import { useRef, useState, type ReactNode } from "react";

type Props = {
  direction: "row" | "column";
  /// Initial size of the first pane, as a fraction of the container.
  initial?: number;
  min?: number;
  children: [ReactNode, ReactNode];
};

/// Two panes with a draggable divider (Wireshark/Burp-style resizable panes).
export function SplitPane({ direction, initial = 0.5, min = 0.15, children }: Props) {
  const [ratio, setRatio] = useState(initial);
  const box = useRef<HTMLDivElement>(null);

  function onPointerDown(e: React.PointerEvent) {
    e.preventDefault();
    const el = box.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const move = (ev: PointerEvent) => {
      const pos = direction === "row" ? (ev.clientX - rect.left) / rect.width : (ev.clientY - rect.top) / rect.height;
      setRatio(Math.min(1 - min, Math.max(min, pos)));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      document.body.classList.remove("resizing");
    };
    document.body.classList.add("resizing");
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  return (
    <div ref={box} className={`split split-${direction}`}>
      <div className="split-pane" style={{ flexBasis: `${ratio * 100}%` }}>
        {children[0]}
      </div>
      <div className="split-divider" onPointerDown={onPointerDown} onDoubleClick={() => setRatio(initial)} />
      <div className="split-pane" style={{ flexBasis: `${(1 - ratio) * 100}%` }}>
        {children[1]}
      </div>
    </div>
  );
}
