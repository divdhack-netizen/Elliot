import { useState } from "react";
import { ProxyScreen } from "./proxy/ProxyScreen";

type Screen = "proxy" | "repeater" | "intruder" | "agent";
const SCREENS: Array<[Screen, string, boolean]> = [
  ["proxy", "Proxy", true],
  ["repeater", "Repeater", false],
  ["intruder", "Intruder", false],
  ["agent", "Agent", false],
];

export default function App() {
  const [screen, setScreen] = useState<Screen>("proxy");
  return (
    <div className="app">
      <header className="appbar">
        <span className="brand">elliot</span>
        <nav className="tabs">
          {SCREENS.map(([k, label, ready]) => (
            <button
              key={k}
              className={screen === k ? "active" : ""}
              disabled={!ready}
              title={ready ? undefined : "Not implemented yet"}
              onClick={() => setScreen(k)}
            >
              {label}
            </button>
          ))}
        </nav>
      </header>
      <main className="screen">{screen === "proxy" && <ProxyScreen />}</main>
    </div>
  );
}
