import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { fetchDoctor, getProfileId } from "../api/client";
import type { GatewayResidualStatusResponse } from "../api/types";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import {
  CONSENT_FILE_BACKED_HONESTY,
  CONSENT_MULTI_REPLICA_SHARED_HONESTY,
  CONSENT_SAME_HOST_RELOAD_HONESTY,
  CONSENT_STORES_TOKENS_HONESTY,
  formatPrincipalCacheHygiene,
  formatResidualBool,
  GATEWAY_READY_RESIDUAL_HONESTY,
  HA_MULTI_REPLICA_RESIDUAL_HONESTY,
  LIVE_PIN_RESIDUAL_HONESTY,
  pickProgressiveConsentFields,
  pickResidualLivePinFields,
  pickResidualRateCacheFields,
  PRINCIPAL_CACHE_HYGIENE_HONESTY,
  PRINCIPAL_CACHE_PROCESS_HONESTY,
  SHARED_API_TOKEN_VAULT_FILE_HONESTY,
  SHARED_JWKS_FILE_HONESTY,
  SHARED_JWT_VAULT_FILE_HONESTY,
  SHARED_SUBJECT_RATE_FILE_HONESTY,
  SHARED_TOKEN_CACHE_FILE_HONESTY,
  SUBJECT_LIMITER_MAX_SUBJECTS_HONESTY,
  SUBJECT_SLOTS_PROCESS_LOCAL_HONESTY,
} from "../lib/residualStatus";

function statusClass(status: string): string {
  const s = status.toLowerCase();
  if (s === "ok") return "ok";
  if (s === "warn") return "warn";
  if (s === "fail") return "fail";
  return "skip";
}

/**
 * HOST-007 SPA Doctor residual lite: show embedded gateway_residual_status
 * after overall when present. Same secret-free rate/cache helpers as Overview.
 */
function DoctorGatewayResidualCard({
  data,
}: {
  data: GatewayResidualStatusResponse;
}) {
  const rateCache = pickResidualRateCacheFields(data);
  const livePins = pickResidualLivePinFields(data);
  const consent = pickProgressiveConsentFields(data);
  const hygiene = formatPrincipalCacheHygiene(
    rateCache.principal_cache_max_entries,
    rateCache.principal_cache_ttl_seconds,
  );
  const doc = data.doc || "docs/gateway/live-pin-blockers.md";
  const showConsent = Boolean(data.progressive_consent);

  return (
    <div className="card">
      <h2>Gateway residual status</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        HOST-007 doctor embed (
        <code>gateway_residual_status</code>) — same secret-free map as{" "}
        <code>gateway residual-status</code> / Overview residual card.
        Informational only; does not drive overall. Live pin residual honesty:{" "}
        <code>{doc}</code>
        {doc.includes("live-pin-blockers") ? null : (
          <>
            {" "}
            · see also <code>docs/gateway/live-pin-blockers.md</code>
          </>
        )}
        . Never tokens or subjects; not live GO.
      </p>
      <dl className="dl">
        <dt>mode_a_live_obtain_qualified</dt>
        <dd>
          {formatResidualBool(livePins.mode_a_live_obtain_qualified)}{" "}
          <span className="muted">({LIVE_PIN_RESIDUAL_HONESTY})</span>
        </dd>
        <dt>mode_b_live_rs_qualified</dt>
        <dd>
          {formatResidualBool(livePins.mode_b_live_rs_qualified)}{" "}
          <span className="muted">({LIVE_PIN_RESIDUAL_HONESTY})</span>
        </dd>
        <dt>mode_c_live_agentcore_qualified</dt>
        <dd>
          {formatResidualBool(livePins.mode_c_live_agentcore_qualified)}{" "}
          <span className="muted">({LIVE_PIN_RESIDUAL_HONESTY})</span>
        </dd>
        <dt>gateway_ready</dt>
        <dd>
          {formatResidualBool(livePins.gateway_ready)}{" "}
          <span className="muted">({GATEWAY_READY_RESIDUAL_HONESTY})</span>
        </dd>
        <dt>ha_multi_replica</dt>
        <dd>
          {formatResidualBool(livePins.ha_multi_replica)}{" "}
          <span className="muted">({HA_MULTI_REPLICA_RESIDUAL_HONESTY})</span>
        </dd>
        <dt>shared_subject_rate_file</dt>
        <dd>
          {rateCache.shared_subject_rate_file ? "yes" : "no"}{" "}
          <span className="muted">({SHARED_SUBJECT_RATE_FILE_HONESTY})</span>
        </dd>
        {typeof rateCache.subject_limiter_max_subjects === "number" ? (
          <>
            <dt>subject_limiter_max_subjects</dt>
            <dd>
              {rateCache.subject_limiter_max_subjects}{" "}
              <span className="muted">({SUBJECT_LIMITER_MAX_SUBJECTS_HONESTY})</span>
            </dd>
          </>
        ) : null}
        <dt>subject_slots_process_local</dt>
        <dd>
          {formatResidualBool(rateCache.subject_slots_process_local)}{" "}
          <span className="muted">({SUBJECT_SLOTS_PROCESS_LOCAL_HONESTY})</span>
        </dd>
        <dt>shared_principal_cache_file</dt>
        <dd>
          {rateCache.shared_principal_cache_file ? "yes" : "no"}{" "}
          <span className="muted">
            (same-host FilePrincipalCache lite when true; path never shown; not
            multi-pod)
          </span>
        </dd>
        <dt>shared_jwks_file</dt>
        <dd>
          {rateCache.shared_jwks_file ? "yes" : "no"}{" "}
          <span className="muted">({SHARED_JWKS_FILE_HONESTY})</span>
        </dd>
        <dt>shared_token_cache_file</dt>
        <dd>
          {rateCache.shared_token_cache_file ? "yes" : "no"}{" "}
          <span className="muted">({SHARED_TOKEN_CACHE_FILE_HONESTY})</span>
        </dd>
        <dt>shared_api_token_vault_file</dt>
        <dd>
          {rateCache.shared_api_token_vault_file ? "yes" : "no"}{" "}
          <span className="muted">({SHARED_API_TOKEN_VAULT_FILE_HONESTY})</span>
        </dd>
        <dt>shared_jwt_vault_file</dt>
        <dd>
          {rateCache.shared_jwt_vault_file ? "yes" : "no"}{" "}
          <span className="muted">({SHARED_JWT_VAULT_FILE_HONESTY})</span>
        </dd>
        <dt>principal_cache_entries</dt>
        <dd>
          {typeof rateCache.principal_cache_entries === "number"
            ? rateCache.principal_cache_entries
            : "—"}{" "}
          <span className="muted">
            (count only; never subjects;{" "}
            {rateCache.principal_cache_process_note ||
              PRINCIPAL_CACHE_PROCESS_HONESTY}
            )
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
        {showConsent ? (
          <>
            <dt>progressive_consent.file_backed</dt>
            <dd>
              {consent.file_backed ? "yes" : "no"}{" "}
              <span className="muted">({CONSENT_FILE_BACKED_HONESTY})</span>
            </dd>
            <dt>progressive_consent.same_host_reload_before_persist</dt>
            <dd>
              {consent.same_host_reload_before_persist ? "yes" : "no"}{" "}
              <span className="muted">({CONSENT_SAME_HOST_RELOAD_HONESTY})</span>
            </dd>
            <dt>progressive_consent.multi_replica_shared</dt>
            <dd>
              {formatResidualBool(consent.multi_replica_shared)}{" "}
              <span className="muted">({CONSENT_MULTI_REPLICA_SHARED_HONESTY})</span>
            </dd>
            <dt>progressive_consent.stores_tokens</dt>
            <dd>
              {formatResidualBool(consent.stores_tokens)}{" "}
              <span className="muted">({CONSENT_STORES_TOKENS_HONESTY})</span>
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
        {data.residual_note ? (
          <>
            <dt>residual_note</dt>
            <dd className="muted">{data.residual_note}</dd>
          </>
        ) : null}
        <dt>doc</dt>
        <dd>
          <code>{doc}</code>
        </dd>
      </dl>
    </div>
  );
}

export function DoctorPage() {
  const profileId = getProfileId();
  const [offline, setOffline] = useState(true);
  const [runKey, setRunKey] = useState(0);

  const q = useQuery({
    queryKey: ["doctor", profileId, offline, runKey],
    queryFn: () => fetchDoctor(profileId, offline),
    retry: 1,
  });

  const gatewayResidual =
    q.isSuccess && q.data.gateway_residual_status
      ? q.data.gateway_residual_status
      : undefined;

  return (
    <>
      <h1 className="page-title">Doctor</h1>
      <p className="page-sub">
        Bounded diagnostics for profile <code>{profileId}</code> (
        <code>
          GET /admin/v1/profiles/{"{id}"}/doctor?offline={offline ? "1" : "0"}
        </code>
        ). Online mode requires a configured admin shared secret.
      </p>

      <div className="toolbar">
        <label className="check-label">
          <input
            type="checkbox"
            checked={offline}
            onChange={(ev) => setOffline(ev.target.checked)}
          />
          Offline (default; no Jenkins whoAmI)
        </label>
        <button
          type="button"
          className="btn btn-primary"
          disabled={q.isFetching}
          onClick={() => setRunKey((n) => n + 1)}
        >
          {q.isFetching ? "Running…" : "Run doctor"}
        </button>
      </div>

      {q.isLoading && <Loading />}
      {q.isError && <ErrorBanner error={q.error} />}

      {q.isSuccess && (
        <>
          <div className="card">
            <h2>Overall</h2>
            <dl className="dl">
              <dt>profileId</dt>
              <dd>{q.data.profileId}</dd>
              <dt>overall</dt>
              <dd>
                <span className={`tag ${statusClass(String(q.data.overall))}`}>
                  {q.data.overall}
                </span>
              </dd>
              <dt>version</dt>
              <dd>{q.data.version || "—"}</dd>
              <dt>commit</dt>
              <dd>{q.data.commit || "—"}</dd>
            </dl>
          </div>

          {gatewayResidual ? (
            <DoctorGatewayResidualCard data={gatewayResidual} />
          ) : null}

          <div className="card">
            <h2>Checks</h2>
            {!q.data.checks?.length ? (
              <p className="muted">No checks returned.</p>
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th>name</th>
                    <th>status</th>
                    <th>message</th>
                  </tr>
                </thead>
                <tbody>
                  {q.data.checks.map((c) => (
                    <tr key={c.name}>
                      <td className="mono">{c.name}</td>
                      <td>
                        <span
                          className={`tag ${statusClass(String(c.status))}`}
                        >
                          {c.status}
                        </span>
                      </td>
                      <td>{c.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
    </>
  );
}
