import { useState } from "react";

/// What the backend reports about the running proxy's CA key.
export type CaStatus = {
  /// "keychain" | "encrypted_file": the backend that actually answered.
  backend: string;
  caDir: string;
  legacyMigrated: boolean;
};

/// Guided install of the Elliot root CA (replaces the old `alert(pem)`), plus
/// the honest answer to "where is the private key?".
export function CaDialog({
  pem,
  status,
  onClose,
}: {
  pem: string;
  status: CaStatus | null;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const backend =
    status?.backend === "keychain"
      ? "macOS Keychain / OS keychain"
      : status?.backend === "encrypted_file"
        ? "encrypted file (ca.key.enc)"
        : null;
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="modal" onMouseDown={(e) => e.stopPropagation()}>
        <header className="modal-head">
          <span>Elliot CA certificate</span>
          <button className="icon-btn" onClick={onClose} title="Close">✕</button>
        </header>
        <div className="modal-body">
          <p className="muted">
            To inspect HTTPS, the browser must trust Elliot's root CA. Install it only on machines you
            use for testing, and remove it when you are done.
          </p>
          <p className="muted small">
            Private key protected by: <strong>{backend ?? "unknown (proxy not running)"}</strong>
            {status?.legacyMigrated && (
              <>
                {" — "}a legacy plain-text <code>ca.key</code> was imported and removed
              </>
            )}
            {status && <span className="mono"> · {status.caDir}</span>}
          </p>
          <ol className="steps">
            <li>Copy the certificate below and save it as <code>elliot-ca.pem</code>.</li>
            <li>
              macOS: open it in Keychain Access, add it to the <b>System</b> keychain and set
              <i> When using this certificate</i> to <b>Always Trust</b>.
            </li>
            <li>Firefox uses its own store: Settings → Certificates → Import.</li>
            <li>Point the browser's HTTP and HTTPS proxy at the listen address.</li>
          </ol>
          <pre className="code pem">{pem}</pre>
        </div>
        <footer className="modal-foot">
          <button
            className="btn primary"
            onClick={() =>
              navigator.clipboard.writeText(pem).then(() => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1200);
              })
            }
          >
            {copied ? "Copied ✓" : "Copy PEM"}
          </button>
          <button className="btn" onClick={onClose}>Close</button>
        </footer>
      </div>
    </div>
  );
}
