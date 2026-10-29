import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

// A desktop app has no reason to reload its own window, and a reload resets the
// React tree while the proxy keeps running in the backend — leaving a "Start"
// button over a live proxy. Swallow the reload shortcut (Cmd/Ctrl+R) so the
// swipe gesture is not the only way the page could still be reloaded.
window.addEventListener(
  "keydown",
  (e) => {
    if ((e.metaKey || e.ctrlKey) && (e.key === "r" || e.key === "R")) {
      e.preventDefault();
    }
  },
  { capture: true },
);

const container = document.getElementById("root");
if (!container) {
  throw new Error("Elliot: elemento #root non trovato in index.html");
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
);
