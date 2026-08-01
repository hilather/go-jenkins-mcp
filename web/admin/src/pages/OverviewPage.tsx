import { useQuery } from "@tanstack/react-query";
import {
  AdminApiError,
  fetchGatewayResidualStatus,
  fetchGatewayVault,
  fetchHealth,
  fetchVersion,
  getProfileId,
} from "../api/client";
import type { GatewayResidualStatusResponse } from "../api/types";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import {
  formatPrincipalCacheHygiene,
  pickResidualRateCacheFields,
  PRINCIPAL_CACHE_HYGIENE_HONESTY,
  PRINCIPAL_CACHE_PROCESS_HONESTY,
  SHARED_SUBJECT_RATE_FILE_HONESTY,
} from "../lib/residualStatus";

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

  const residual = useQuery({
    queryKey: ["gateway-residual-status"],
    queryFn: fetchGatewayResidualStatus,
    retry: false,
    enabled: health.isSuccess,
  });

  const apiDown = health.isError;
  // Hide card when older BFF lacks the route (404) or BFF is down.
  const vaultMissing =
    vault.isError &&
    vault.error instanceof AdminApiError &&
    vault.error.status === 404;
  const residualMissing =
    residual.isError &&
    residual.error instanceof AdminApiError &&
    residual.error.status === 404;

  // Mode C progressive consent residual (OAUTH-010): show when residual note
  // is present or Mode C is in health mode fields (never secrets).
  const modeC =
    health.isSuccess &&
    (Boolean(health.data.progressiveConsentResidual) ||
      health.data.credentialMode === "agentcore_3lo_obo" ||
      Boolean(health.data.enabledModes?.includes("agentcore_3lo_obo")));

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
            <dt>sessionAffinityRecommended</dt>
            <dd>
              {health.data.sessionAffinityRecommended ? "yes" : "no"}{" "}
              <span className="muted">
                (HOST-008 sticky Service scaffold when multi-user; not multi-replica Done)
              </span>
            </dd>
            <dt>multiPodVaultResidual</dt>
            <dd>
              {health.data.multiPodVaultResidual !== false ? "yes" : "no"}{" "}
              <span className="muted">
                (HOST-008 multi-pod durable vault residual honesty — not multi-replica Done)
              </span>
            </dd>
            <dt>kubernetesEnvDetected</dt>
            <dd>
              {health.data.kubernetesEnvDetected ? "yes" : "no"}{" "}
              <span className="muted">
                (KUBERNETES_SERVICE_HOST; in-cluster residual only)
              </span>
            </dd>
            <dt>rateEnabled</dt>
            <dd>
              {health.data.rateEnabled ? "yes" : "no"}{" "}
              <span className="muted">(HOST-006 process-local residual; not multi-replica shared rate)</span>
            </dd>
            {typeof health.data.ratePerMinute === "number" ? (
              <>
                <dt>ratePerMinute</dt>
                <dd>
                  {health.data.ratePerMinute}{" "}
                  <span className="muted">(resolved default or env; 0 when disabled)</span>
                </dd>
              </>
            ) : null}
            {typeof health.data.rateBurst === "number" ? (
              <>
                <dt>rateBurst</dt>
                <dd>
                  {health.data.rateBurst}{" "}
                  <span className="muted">(process-local residual; multi-replica shared rate residual)</span>
                </dd>
              </>
            ) : null}
            <dt>sharedSubjectRateFile</dt>
            <dd>
              {health.data.sharedSubjectRateFile ? "yes" : "no"}{" "}
              <span className="muted">
                (HOST-008 same-host file rate lite when path set; not multi-pod HA —
                path never shown)
              </span>
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

      {health.isSuccess && health.data.kubernetesEnvDetected && (
        <div className="card">
          <h2>Multi-pod residual checklist (HOST-008)</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            <code>kubernetesEnvDetected=true</code> (
            <code>KUBERNETES_SERVICE_HOST</code>). Secret-free honesty only —
            not multi-replica Done. Doctor parity:{" "}
            <code>gateway_status.multi_pod_vault_residual</code>. See{" "}
            <code>docs/gateway/deployment.md</code> §9.
          </p>
          <ul className="muted" style={{ margin: 0, paddingLeft: "1.2rem" }}>
            <li>
              Sticky sessions or shared session store (
              <code>sessionAffinityRecommended</code> when multi-user)
            </li>
            <li>
              Durable shared vault (not emptyDir) —{" "}
              <code>multiPodVaultResidual=true</code>
            </li>
            <li>Shared subject rate (process-local rate residual today)</li>
            <li>Shared Obtain / token cache across pods</li>
            <li>
              <code>haMultiReplica=false</code> until runtime HA
            </li>
          </ul>
          {health.data.residual ? (
            <p className="muted" style={{ marginBottom: 0 }}>
              <strong>health residual:</strong> {health.data.residual}
            </p>
          ) : null}
        </div>
      )}

      {modeC && health.isSuccess && (
        <div className="card">
          <h2>Progressive consent residual (Mode C)</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            OAUTH-010 / GWY-001 honesty from{" "}
            <code>GET /admin/v1/health</code> (
            <code>gateway.NewProgressiveConsentResidual</code>). Static /
            secret-free — never live Obtain, tokens, or{" "}
            <code>authorization_url</code> query strings in admin JSON.
          </p>
          <dl className="dl">
            <dt>progressiveConsentMetadataDoneStar</dt>
            <dd>
              {health.data.progressiveConsentMetadataDoneStar ? "yes" : "no"}{" "}
              <span className="muted">
                (ConsentRequired → authorization_url + session_id only)
              </span>
            </dd>
            <dt>progressiveConsentBrowser3loAutomated</dt>
            <dd>
              {health.data.progressiveConsentBrowser3loAutomated
                ? "yes"
                : "no"}{" "}
              <span className="muted">(browser 3LO not automated residual)</span>
            </dd>
            {health.data.progressiveConsentResidual ? (
              <>
                <dt>progressiveConsentResidual</dt>
                <dd className="muted">{health.data.progressiveConsentResidual}</dd>
              </>
            ) : null}
          </dl>
        </div>
      )}

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

      {!residualMissing && (
        <div className="card">
          <h2>Gateway residual status</h2>
          <p className="muted" style={{ marginTop: 0 }}>
            HOST-007 unified residual snapshot (
            <code>GET /admin/v1/gateway/residual-status</code>) — same secret-free
            fields as <code>jenkins-mcp gateway residual-status</code>. Env/static
            honesty only; never tokens or subjects. Live pin residual honesty:{" "}
            <code>docs/gateway/live-pin-blockers.md</code>.
          </p>
          {residual.isLoading && health.isSuccess && <Loading />}
          {residual.isError &&
            !(residual.error instanceof AdminApiError && residual.error.status === 404) && (
              <ErrorBanner error={residual.error} />
            )}
          {residual.isSuccess ? (
            <ResidualStatusDl data={residual.data} />
          ) : (
            !residual.isLoading &&
            !residual.isError && (
              <p className="muted">Residual status not loaded.</p>
            )
          )}
        </div>
      )}

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
              <dt>sessionAffinityRecommended</dt>
              <dd>
                {vault.data.sessionAffinityRecommended ? "yes" : "no"}{" "}
                <span className="muted">(sticky scaffold honesty; not multi-replica Done)</span>
              </dd>
              <dt>multiPodVaultResidual</dt>
              <dd>
                {vault.data.multiPodVaultResidual !== false ? "yes" : "no"}{" "}
                <span className="muted">(HOST-008 multi-pod vault residual; not multi-replica Done)</span>
              </dd>
              <dt>kubernetesEnvDetected</dt>
              <dd>
                {vault.data.kubernetesEnvDetected ? "yes" : "no"}{" "}
                <span className="muted">(in-cluster residual; not HA Done)</span>
              </dd>
              <dt>rateEnabled</dt>
              <dd>
                {vault.data.rateEnabled ? "yes" : "no"}{" "}
                <span className="muted">(process-local env residual)</span>
              </dd>
              {typeof vault.data.ratePerMinute === "number" ? (
                <>
                  <dt>ratePerMinute</dt>
                  <dd>
                    {vault.data.ratePerMinute}{" "}
                    <span className="muted">(0 when disabled)</span>
                  </dd>
                </>
              ) : null}
              {typeof vault.data.rateBurst === "number" ? (
                <>
                  <dt>rateBurst</dt>
                  <dd>
                    {vault.data.rateBurst}{" "}
                    <span className="muted">(HOST-006 process-local; not multi-replica shared)</span>
                  </dd>
                </>
              ) : null}
              <dt>sharedSubjectRateFile</dt>
              <dd>
                {vault.data.sharedSubjectRateFile ? "yes" : "no"}{" "}
                <span className="muted">
                  (HOST-008 same-host file rate lite; not multi-pod HA — path never shown)
                </span>
              </dd>
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
            Mode C progressive consent: metadata path Done* on health; browser
            3LO not automated (OAUTH-010). Admin never returns authorize URLs
            with secrets.
          </li>
          <li>
            Multi-pod / HA (HOST-008): health and vault always surface{" "}
            <code>multiPodVaultResidual</code> (honest residual, not Done).
            When <code>kubernetesEnvDetected</code>, Overview shows the multi-pod
            residual checklist (sticky, shared vault, rate, Obtain cache). Never
            multi-replica Done from k8s env alone.{" "}
            <code>sharedSubjectRateFile</code> is same-host lite only.
          </li>
          <li>
            Gateway residual status (HOST-007):{" "}
            <code>GET /admin/v1/gateway/residual-status</code> matches CLI{" "}
            <code>gateway residual-status</code> (modes, multi_user, HA, consent,
            rate, <code>shared_subject_rate_file</code>, principal_cache count +
            optional max/ttl, oauth009_offline). Rate file is same-host lite only;
            principal_cache_entries is this admin BFF process. See{" "}
            <code>docs/gateway/live-pin-blockers.md</code>. Never live production
            GO from admin JSON.
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

/** HOST-007 residual-status card body (snake_case CLI/BFF fields). */
function ResidualStatusDl({ data }: { data: GatewayResidualStatusResponse }) {
  const rateCache = pickResidualRateCacheFields(data);
  const hygiene = formatPrincipalCacheHygiene(
    rateCache.principal_cache_max_entries,
    rateCache.principal_cache_ttl_seconds,
  );

  return (
    <dl className="dl">
      <dt>mode_a / mode_b / mode_c enabled</dt>
      <dd>
        {data.mode_a_enabled ? "A" : "—"}
        {" / "}
        {data.mode_b_enabled ? "B" : "—"}
        {" / "}
        {data.mode_c_enabled ? "C" : "—"}{" "}
        <span className="muted">(config enablement only; not live GO)</span>
      </dd>
      <dt>mode_matrix</dt>
      <dd>
        primary <code>{data.mode_matrix?.primary || "—"}</code>
        {data.mode_matrix?.enabled?.length ? (
          <>
            {" "}
            · enabled{" "}
            {data.mode_matrix.enabled.map((m) => (
              <code key={m} style={{ marginRight: "0.35rem" }}>
                {m}
              </code>
            ))}
          </>
        ) : null}
      </dd>
      <dt>multi_user_enabled</dt>
      <dd>
        {data.multi_user_enabled ? "yes (foundation residual)" : "no"}
      </dd>
      <dt>ha_multi_replica</dt>
      <dd>
        {data.ha_multi_replica ? "yes" : "no"}{" "}
        <span className="muted">(HOST-008 Tier A single-replica default)</span>
      </dd>
      <dt>session_affinity_recommended</dt>
      <dd>
        {data.session_affinity_recommended ? "yes" : "no"}{" "}
        <span className="muted">(sticky scaffold honesty; not multi-replica Done)</span>
      </dd>
      <dt>multi_pod_vault_residual</dt>
      <dd>
        {data.multi_pod_vault_residual !== false ? "yes" : "no"}{" "}
        <span className="muted">(always residual until multi-pod HA)</span>
      </dd>
      <dt>kubernetes_env_detected</dt>
      <dd>
        {data.kubernetes_env_detected ? "yes" : "no"}{" "}
        <span className="muted">(in-cluster residual only)</span>
      </dd>
      {data.multi_pod_residual_checklist ? (
        <>
          <dt>multi_pod_residual_checklist</dt>
          <dd className="muted">{data.multi_pod_residual_checklist}</dd>
        </>
      ) : null}
      <dt>rateEnabled / ratePerMinute / rateBurst</dt>
      <dd>
        {data.rateEnabled ? "on" : "off"}
        {" · "}
        {typeof data.ratePerMinute === "number" ? data.ratePerMinute : "—"}
        {" / "}
        {typeof data.rateBurst === "number" ? data.rateBurst : "—"}{" "}
        <span className="muted">(HOST-006 process-local; not multi-replica shared)</span>
      </dd>
      <dt>shared_subject_rate_file</dt>
      <dd>
        {rateCache.shared_subject_rate_file ? "yes" : "no"}{" "}
        <span className="muted">({SHARED_SUBJECT_RATE_FILE_HONESTY})</span>
      </dd>
      {typeof rateCache.subject_rate_max_subjects === "number" ? (
        <>
          <dt>subject_rate_max_subjects</dt>
          <dd>
            {rateCache.subject_rate_max_subjects}{" "}
            <span className="muted">(rate map hygiene; omit = unlimited)</span>
          </dd>
        </>
      ) : null}
      <dt>shared_principal_cache_file</dt>
      <dd>
        {rateCache.shared_principal_cache_file ? "yes" : "no"}{" "}
        <span className="muted">
          (same-host FilePrincipalCache lite when true; path never shown; not multi-pod)
        </span>
      </dd>
      <dt>principal_cache_entries</dt>
      <dd>
        {typeof rateCache.principal_cache_entries === "number"
          ? rateCache.principal_cache_entries
          : "—"}{" "}
        <span className="muted">
          (count only; never subjects;{" "}
          {rateCache.principal_cache_process_note || PRINCIPAL_CACHE_PROCESS_HONESTY})
        </span>
      </dd>
      {hygiene ? (
        <>
          <dt>principal_cache max / ttl</dt>
          <dd>
            {hygiene}{" "}
            <span className="muted">({PRINCIPAL_CACHE_HYGIENE_HONESTY})</span>
          </dd>
        </>
      ) : null}
      <dt>residual_id (Mode B)</dt>
      <dd>
        <code>{data.residual_id || "oauth009_offline"}</code>{" "}
        <span className="muted">
          (oauth009_offline=
          {data.oauth009_offline !== false ? "true" : "false"}; live RS residual)
        </span>
      </dd>
      <dt>residual_ids</dt>
      <dd>
        {data.residual_ids?.length ? (
          data.residual_ids.map((id) => (
            <code key={id} style={{ marginRight: "0.35rem" }}>
              {id}
            </code>
          ))
        ) : (
          <span className="muted">—</span>
        )}
      </dd>
      {data.progressive_consent ? (
        <>
          <dt>progressive_consent (Mode C residual)</dt>
          <dd>
            metadata_done*
            {data.progressive_consent.metadata_path_done_star ? "=yes" : "=no"}
            {" · browser_3lo_automated="}
            {data.progressive_consent.browser_3lo_automated ? "yes" : "no"}
          </dd>
        </>
      ) : null}
      {data.progressive_consent_residual ? (
        <>
          <dt>progressive_consent_residual</dt>
          <dd className="muted">{data.progressive_consent_residual}</dd>
        </>
      ) : null}
      {data.residual_note ? (
        <>
          <dt>residual_note</dt>
          <dd className="muted">{data.residual_note}</dd>
        </>
      ) : null}
      <dt>doc</dt>
      <dd>
        <code>{data.doc || "docs/gateway/live-pin-blockers.md"}</code>
      </dd>
    </dl>
  );
}
