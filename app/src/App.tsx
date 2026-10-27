import { useCallback, useState } from "react";
import { AgentScreen } from "./agent/AgentScreen";
import type { ContextInput } from "./agent/types";
import { invoke } from "./proxy/backend";
import { CaptureScreen } from "./capture/CaptureScreen";
import { ProxyScreen } from "./proxy/ProxyScreen";
import { IntruderScreen } from "./intruder/IntruderScreen";
import { RepeaterScreen } from "./repeater/RepeaterScreen";
import type { AttackArgs, RepeatArgs } from "./replay/types";

type Screen = "proxy" | "capture" | "repeater" | "intruder" | "agent";
const SCREENS: Array<[Screen, string, boolean]> = [
  ["proxy", "Proxy", true],
  ["capture", "Capture", true],
  ["repeater", "Repeater", true],
  ["intruder", "Intruder", true],
  ["agent", "Agent", true],
];

export default function App() {
  const [screen, setScreen] = useState<Screen>("proxy");
  // Work handed from Capture (or HTTP history) to the active tools. A fresh
  // object every time, so repeating the same hand-off still resets the form.
  const [repeaterSeed, setRepeaterSeed] = useState<RepeatArgs | null>(null);
  const [intruderSeed, setIntruderSeed] = useState<AttackArgs | null>(null);

  const toRepeater = useCallback((args: RepeatArgs) => {
    setRepeaterSeed({ ...args });
    setScreen("repeater");
  }, []);

  const toIntruder = useCallback((args: AttackArgs) => {
    setIntruderSeed({ ...args });
    setScreen("intruder");
  }, []);

  /// Hand captured material to the agent's context tray. The backend emits the
  /// updated tray on `agent://context`, so the chips follow without a reload.
  const toAgent = useCallback(async (item: ContextInput) => {
    try {
      await invoke("agent_attach_context", { item });
      setScreen("agent");
    } catch (e) {
      console.error("agent context:", e);
    }
  }, []);

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
      {/* Every screen stays mounted: switching tabs must not throw away a
          repeater request that was being edited. */}
      <main className="screen">
        <div className="pane" style={{ display: screen === "proxy" ? "flex" : "none" }}>
          <ProxyScreen
            onSendToRepeater={toRepeater}
            onSendToIntruder={toIntruder}
            onSendToAgent={(item) => void toAgent(item)}
          />
        </div>
        <div className="pane" style={{ display: screen === "capture" ? "flex" : "none" }}>
          <CaptureScreen
            onSendToRepeater={toRepeater}
            onSendToIntruder={toIntruder}
            onSendToAgent={(item) => void toAgent(item)}
          />
        </div>
        <div className="pane" style={{ display: screen === "repeater" ? "flex" : "none" }}>
          <RepeaterScreen seed={repeaterSeed} />
        </div>
        <div className="pane" style={{ display: screen === "intruder" ? "flex" : "none" }}>
          <IntruderScreen seed={intruderSeed} />
        </div>
        <div className="pane" style={{ display: screen === "agent" ? "flex" : "none" }}>
          <AgentScreen />
        </div>
      </main>
    </div>
  );
}
