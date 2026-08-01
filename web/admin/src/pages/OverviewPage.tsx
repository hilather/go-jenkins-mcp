import { useQuery } from "@tanstack/react-query";
import {
  AdminApiError,
  fetchGatewayVault,
  fetchHealth,
  fetchVersion,
  getProfileId,
} from "../api/client";
import { ErrorBanner, Loading } from "../components/ErrorBanner";

export function OverviewPage() {
  const profileId = getProfileId();

  const health = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    retry: 1,
  });

  const version = useQuery({
    queryKey: ["version"],
    queryFn: fetchVersion,
    retry: 1,
    enabled: health.isSuccess,
  });

  const vault = useQuery({
    queryKey: ["gateway-vault"],
    queryFn: fetchGatewayVault,
    retry: false,
    enabled: health.isSuccess,
  });

  const apiDown = health.isError;
  // Hide card when older BFF lacks the route (404) or BFF is down.
  const vaultMissing =
    vault.isError &&
    vault.error instanceof AdminApiError &&
    vault.error.status === 404;

  return (
    <>
      <h1 className="page-title">Overview</h1>
      <p className="page-sub">
        Profile <code>{profileId}</code> · admin BFF{" "}
        <code>/admin/v1</code>
      </p>

      {apiDown && (
        <div className="banner warn" role="status">
          <strong>Admin BFF unreachable.</strong> Start{" "}
          <code>jenkins-mcp admin serve</code> (UI-002) on{" "}
          <code>127.0.0.1:8787</code>, or run{" "}
          <code>npm run dev</code> with the Vite proxy. This residual is
          expected until the BFF is running — no secrets are required in the
          SPA for health/version.
        </div>
      )}

      {health.isLoading && <Loading />}
      {health.isError && <ErrorBanner error={health.error} />}

      {health.isSuccess && (
        <div className="banner ok" role="status">
          API health: <strong>{health.data.status}</strong>
          {health.data.version ? (
            <>
              {" "}
              · version <code>{health.data.version}</code>
            </>
          ) : null}
          {health.data.commit ? (
            <>
              {" "}
              · commit <code>{health.data.commit}</code>
            </>
          ) : null}
        </div>
      )}

      <div className="card">
        <h2>Health</h2>
        {health.isSuccess ? (
          <dl className="dl">
            <dt>status</dt>
            <dd>{health.data.status}</dd>
            <dt>version</dt>
            <dd>{health.data.version || "—"}</dd>
            <dt>commit</dt>
            <dd>{health.data.commit || "—"}</dd>
            <dt>uiBuild</dt>
            <dd>{health.data.uiBuild || "(none)"}</dd>
            <dt>credentialMode</dt>
            <dd>
              <code>{health.data.credentialMode || "—"}</code>
            </dd>
            <dt>multiUserEnabled</dt>
            <dd>{health.data.multiUserEnabled ? "yes (foundation residual)" : "no"}</dd>
            <dt>gatewayReady</dt>
            <dd>
              {health.data.gatewayReady ? "yes" : "no"}{" "}
              <span className="muted">(admin BFF residual; Ready is serve /readyz)</span>
            </dd>
            <dt>haMultiReplica</dt>
            <dd>
              {health.data.haMultiReplica ? "yes" : "no"}{" "}
              <span className="muted">(HOST-008 Tier A single-replica default)</span>
            </dd>
            {health.data.residual ? (
              <>
                <dt>residual</dt>
                <dd className="muted">{health.data.residual}</dd>
              </>
            ) : null}
          </dl>
        ) : (
          !health.isLoading && (
            <p className="muted">No health payload (BFF offline or error).</p>
          )
        )}
      </div>

      <div className="card">
        <h2>Version</h2>
        {version.isLoading && health.isSuccess && <Loading />}
        {version.isError && <ErrorBanner error={version.error} />}
        {version.isSuccess ? (
          <dl className="dl">
            <dt>version</dt>
            <dd>{version.data.version}</dd>
            <dt>commit</dt>
            <dd>{version.data.commit}</dd>
            <dt>buildTime</dt>
            <dd>{version.data.buildTime}</dd>
            <dt>goVersion</dt>
            <dd>{version.data.goVersion}</dd>
            <dt>os/arch</dt>
            <dd>
              {version.data.os}/{version.data.arch}
            </dd>
          </dl>
        ) : (
          !version.isLoading && (
            <p className="muted">
              Version endpoint not loaded (depends on health).
            </p>
          )
        )}
      </div>

      {!vaultMissing && (
        <div className="card">
          <h2>Gateway vault</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            HOST-011 mode matrix + Mode A inventory (
            <code>GET /admin/v1/gateway/vault</code>). Subjects are{" "}
            <code>SubjectKeyHash</code> only — never tokens. Provision via CLI:
          </p>
          <pre className="mono" style={{ fontSize: "0.85rem", overflow: "auto" }}>
            {`jenkins-mcp gateway vault-put \\
  --subject 'tenant|sub|profile' \\
  --user alice \\
  --token-env MY_TOKEN`}
          </pre>
          {vault.isLoading && health.isSuccess && <Loading />}
          {vault.isError && !(vault.error instanceof AdminApiError && vault.error.status === 404) && (
            <ErrorBanner error={vault.error} />
          )}
          {vault.isSuccess ? (
            <dl className="dl">
              <dt>mode</dt>
              <dd>
                <code>{vault.data.mode || "—"}</code>
              </dd>
              <dt>enabledModes</dt>
              <dd>
                {vault.data.enabledModes?.length
                  ? vault.data.enabledModes.map((m) => (
                      <code key={m} style={{ marginRight: "0.4rem" }}>
                        {m}
                      </code>
                    ))
                  : "—"}
              </dd>
              <dt>multiUserEnabled</dt>
              <dd>{vault.data.multiUserEnabled ? "yes (foundation residual)" : "no"}</dd>
              <dt>haMultiReplica</dt>
              <dd>{vault.data.haMultiReplica ? "yes" : "no (HOST-008 residual)"}</dd>
              <dt>vaultConfigured</dt>
              <dd>{vault.data.vaultConfigured ? "yes" : "no"}</dd>
              <dt>entryCount</dt>
              <dd>{vault.data.entryCount}</dd>
              <dt>subjects (hash)</dt>
              <dd>
                {!vault.data.subjects?.length ? (
                  <span className="muted">none</span>
                ) : (
                  <ul style={{ margin: 0, paddingLeft: "1.2rem" }}>
                    {vault.data.subjects.map((h) => (
                      <li key={h} className="mono">
                        {h.slice(0, 16)}…
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
              {vault.data.residual ? (
                <>
                  <dt>residual</dt>
                  <dd className="muted">{vault.data.residual}</dd>
                </>
              ) : null}
            </dl>
          ) : (
            !vault.isLoading &&
            !vault.isError && (
              <p className="muted">Vault status not loaded.</p>
            )
          )}
        </div>
      )}

      <div className="card">
        <h2>Residuals (v1)</h2>
        <ul className="muted" style={{ margin: 0, paddingLeft: "1.2rem" }}>
          <li>
            Optional admin token: set{" "}
            <code>localStorage[&quot;jenkins-mcp.admin.token&quot;]</code> —
            sent as <code>Authorization: Bearer</code>. Never logged. Better UX
            is UI-003.
          </li>
          <li>
            Policy pilot overlay validate/apply (UI-004) requires{" "}
            <code>policy_admin</code>; signing remains host-side CLI only.
          </li>
          <li>
            Gateway vault <strong>write</strong> is CLI-only (
            <code>jenkins-mcp gateway vault-put</code>); SPA shows status only
            (HOST-009 / HOST-011). Never put tokens in the browser.
          </li>
          <li>
            BFF is loopback-only by default (ADR 0014). No Jenkins tokens in
            this SPA.
          </li>
        </ul>
      </div>
    </>
  );
}
