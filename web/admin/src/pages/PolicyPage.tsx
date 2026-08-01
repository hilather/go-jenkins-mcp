import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  applyPolicyOverlay,
  fetchEffectivePolicy,
  fetchMe,
  fetchPolicyOverlay,
  formatApiError,
  formatDenyListText,
  getProfileId,
  hasPolicyWrite,
  parseDenyListText,
  validatePolicyOverlay,
} from "../api/client";
import type {
  PolicyFieldError,
  PolicyOverlay,
  PolicyValidateResponse,
} from "../api/types";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";

function StringList({
  items,
  emptyLabel = "No entries",
}: {
  items?: string[];
  emptyLabel?: string;
}) {
  if (!items?.length) {
    return (
      <p className="muted deny-list-empty" role="status">
        {emptyLabel}
      </p>
    );
  }
  return (
    <ul className="list-inline">
      {items.map((s) => (
        <li key={s}>{s}</li>
      ))}
    </ul>
  );
}

/** Parse optional positive int draft field; empty string → omit field. */
function parseOptionalPositiveInt(text: string): number | undefined {
  const trim = text.trim();
  if (trim === "") {
    return undefined;
  }
  const n = Number(trim);
  if (Number.isFinite(n) && n > 0) {
    return Math.floor(n);
  }
  return undefined;
}

function emptyDraft(): PolicyOverlay {
  return {
    version: 1,
    force_read_only: true,
    fleet_telemetry_force_off: false,
    mode: "pilot",
    deny_tools: [],
    deny_job_prefixes: [],
    deny_node_names: [],
    deny_view_names: [],
    deny_artifact_paths: [],
    deny_branch_names: [],
  };
}

function overlayFromSource(src?: PolicyOverlay | null): PolicyOverlay {
  if (!src) {
    return emptyDraft();
  }
  return {
    version: src.version || 1,
    force_read_only: Boolean(src.force_read_only),
    fleet_telemetry_force_off: Boolean(src.fleet_telemetry_force_off),
    mode: src.mode || "pilot",
    deny_tools: [...(src.deny_tools ?? [])],
    deny_job_prefixes: [...(src.deny_job_prefixes ?? [])],
    deny_node_names: [...(src.deny_node_names ?? [])],
    deny_view_names: [...(src.deny_view_names ?? [])],
    deny_artifact_paths: [...(src.deny_artifact_paths ?? [])],
    deny_branch_names: [...(src.deny_branch_names ?? [])],
    max_result_bytes: src.max_result_bytes,
    max_tools_per_minute: src.max_tools_per_minute,
    max_tools_burst: src.max_tools_burst,
  };
}

function formatOptionalNumber(n?: number | null): string {
  return n != null ? String(n) : "";
}

export function PolicyPage() {
  const profileId = getProfileId();
  const qc = useQueryClient();

  const meQ = useQuery({
    queryKey: ["me"],
    queryFn: () => fetchMe(),
    retry: 1,
  });
  const canWrite = hasPolicyWrite(meQ.data);

  const effectiveQ = useQuery({
    queryKey: ["policy", "effective", profileId],
    queryFn: () => fetchEffectivePolicy(profileId),
    retry: 1,
  });

  const overlayQ = useQuery({
    queryKey: ["policy", "overlay"],
    queryFn: () => fetchPolicyOverlay(),
    retry: 1,
  });

  const [draft, setDraft] = useState<PolicyOverlay>(() => emptyDraft());
  const [denyText, setDenyText] = useState({
    tools: "",
    jobs: "",
    nodes: "",
    views: "",
    artifacts: "",
    branches: "",
  });
  const [maxBytesText, setMaxBytesText] = useState("");
  const [maxToolsPerMinText, setMaxToolsPerMinText] = useState("");
  const [maxToolsBurstText, setMaxToolsBurstText] = useState("");
  const [seeded, setSeeded] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<PolicyFieldError[]>([]);
  const [preview, setPreview] = useState<PolicyValidateResponse | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // Seed draft from plain overlay when available (once per successful load).
  useEffect(() => {
    if (seeded || !overlayQ.isSuccess) {
      return;
    }
    const o = overlayQ.data.overlay;
    if (overlayQ.data.available && o) {
      const next = overlayFromSource(o);
      setDraft(next);
      setDenyText({
        tools: formatDenyListText(next.deny_tools),
        jobs: formatDenyListText(next.deny_job_prefixes),
        nodes: formatDenyListText(next.deny_node_names),
        views: formatDenyListText(next.deny_view_names),
        artifacts: formatDenyListText(next.deny_artifact_paths),
        branches: formatDenyListText(next.deny_branch_names),
      });
      setMaxBytesText(formatOptionalNumber(next.max_result_bytes));
      setMaxToolsPerMinText(formatOptionalNumber(next.max_tools_per_minute));
      setMaxToolsBurstText(formatOptionalNumber(next.max_tools_burst));
    } else if (effectiveQ.isSuccess) {
      // Fallback seed from effective (still pilot fields only).
      const e = effectiveQ.data;
      const next: PolicyOverlay = {
        version: 1,
        force_read_only: e.force_read_only,
        fleet_telemetry_force_off: Boolean(e.fleet_telemetry_force_off),
        mode: e.mode || "pilot",
        deny_tools: [...(e.deny_tools ?? [])],
        deny_job_prefixes: [...(e.deny_job_prefixes ?? [])],
        deny_node_names: [...(e.deny_node_names ?? [])],
        deny_view_names: [...(e.deny_view_names ?? [])],
        deny_artifact_paths: [...(e.deny_artifact_paths ?? [])],
        deny_branch_names: [...(e.deny_branch_names ?? [])],
        max_result_bytes: e.max_result_bytes,
        max_tools_per_minute: e.max_tools_per_minute,
        max_tools_burst: e.max_tools_burst,
      };
      setDraft(next);
      setDenyText({
        tools: formatDenyListText(next.deny_tools),
        jobs: formatDenyListText(next.deny_job_prefixes),
        nodes: formatDenyListText(next.deny_node_names),
        views: formatDenyListText(next.deny_view_names),
        artifacts: formatDenyListText(next.deny_artifact_paths),
        branches: formatDenyListText(next.deny_branch_names),
      });
      setMaxBytesText(formatOptionalNumber(next.max_result_bytes));
      setMaxToolsPerMinText(formatOptionalNumber(next.max_tools_per_minute));
      setMaxToolsBurstText(formatOptionalNumber(next.max_tools_burst));
    }
    setSeeded(true);
  }, [overlayQ.isSuccess, overlayQ.data, effectiveQ.isSuccess, effectiveQ.data, seeded]);

  const builtOverlay = useMemo((): PolicyOverlay => {
    return {
      version: 1,
      force_read_only: draft.force_read_only,
      fleet_telemetry_force_off: Boolean(draft.fleet_telemetry_force_off),
      mode: draft.mode || "pilot",
      deny_tools: parseDenyListText(denyText.tools),
      deny_job_prefixes: parseDenyListText(denyText.jobs),
      deny_node_names: parseDenyListText(denyText.nodes),
      deny_view_names: parseDenyListText(denyText.views),
      deny_artifact_paths: parseDenyListText(denyText.artifacts),
      deny_branch_names: parseDenyListText(denyText.branches),
      max_result_bytes: parseOptionalPositiveInt(maxBytesText),
      max_tools_per_minute: parseOptionalPositiveInt(maxToolsPerMinText),
      max_tools_burst: parseOptionalPositiveInt(maxToolsBurstText),
    };
  }, [
    draft.force_read_only,
    draft.fleet_telemetry_force_off,
    draft.mode,
    denyText,
    maxBytesText,
    maxToolsPerMinText,
    maxToolsBurstText,
  ]);

  const validateMut = useMutation({
    mutationFn: () => validatePolicyOverlay(builtOverlay, profileId),
    onSuccess: (data) => {
      setPreview(data);
      setFieldErrors(data.errors ?? []);
      setStatusMsg(data.valid ? "Validation OK (dry-run)" : "Validation failed");
    },
    onError: (err) => {
      const { code, message } = formatApiError(err);
      setStatusMsg(`${code}: ${message}`);
      setFieldErrors([]);
      setPreview(null);
    },
  });

  const applyMut = useMutation({
    mutationFn: () => applyPolicyOverlay(builtOverlay, profileId),
    onSuccess: async (data) => {
      setConfirmOpen(false);
      if (!data.applied) {
        setFieldErrors(data.errors ?? []);
        setStatusMsg(data.notes?.[0] || "Apply refused");
        return;
      }
      setFieldErrors([]);
      setStatusMsg("Policy overlay applied");
      setSeeded(false);
      await qc.invalidateQueries({ queryKey: ["policy"] });
    },
    onError: (err) => {
      setConfirmOpen(false);
      const { code, message } = formatApiError(err);
      setStatusMsg(`${code}: ${message}`);
    },
  });

  const errorsByField = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const e of fieldErrors) {
      const list = m.get(e.field) ?? [];
      list.push(e.message);
      m.set(e.field, list);
    }
    return m;
  }, [fieldErrors]);

  return (
    <>
      <PageHeader title="Policy">
        Profile <code>{profileId}</code> · effective + overlay (UI-004)
      </PageHeader>

      {meQ.isError && <ErrorBanner error={meQ.error} />}
      {effectiveQ.isLoading && <Loading />}
      {effectiveQ.isError && <ErrorBanner error={effectiveQ.error} />}

      {effectiveQ.isSuccess && (
        <>
          <div className="card">
            <h2>Effective policy (viewer)</h2>
            <dl className="dl">
              <dt>profile_id</dt>
              <dd>{effectiveQ.data.profile_id || profileId}</dd>
              <dt>policy_present</dt>
              <dd>{String(effectiveQ.data.policy_present)}</dd>
              <dt>signature_state</dt>
              <dd>{effectiveQ.data.signature_state}</dd>
              <dt>force_read_only</dt>
              <dd>{String(effectiveQ.data.force_read_only)}</dd>
              <dt>fleet_telemetry_force_off</dt>
              <dd>{String(Boolean(effectiveQ.data.fleet_telemetry_force_off))}</dd>
              <dt>mode</dt>
              <dd>{effectiveQ.data.mode || "—"}</dd>
              <dt>max_result_bytes</dt>
              <dd>
                {effectiveQ.data.max_result_bytes != null
                  ? String(effectiveQ.data.max_result_bytes)
                  : "—"}
              </dd>
              <dt>max_tools_per_minute</dt>
              <dd>
                {effectiveQ.data.max_tools_per_minute != null
                  ? String(effectiveQ.data.max_tools_per_minute)
                  : "—"}
              </dd>
              <dt>max_tools_burst</dt>
              <dd>
                {effectiveQ.data.max_tools_burst != null
                  ? String(effectiveQ.data.max_tools_burst)
                  : "—"}
              </dd>
              <dt>bundle_seq</dt>
              <dd>
                {effectiveQ.data.bundle_seq != null
                  ? String(effectiveQ.data.bundle_seq)
                  : "—"}
              </dd>
              <dt>key_id</dt>
              <dd>{effectiveQ.data.key_id || "—"}</dd>
            </dl>
          </div>

          <div className="card">
            <h2>Deny lists (effective)</h2>
            <dl className="dl">
              <dt>deny_tools</dt>
              <dd>
                <StringList items={effectiveQ.data.deny_tools} />
              </dd>
              <dt>deny_job_prefixes</dt>
              <dd>
                <StringList items={effectiveQ.data.deny_job_prefixes} />
              </dd>
              <dt>deny_node_names</dt>
              <dd>
                <StringList items={effectiveQ.data.deny_node_names} />
              </dd>
              <dt>deny_view_names</dt>
              <dd>
                <StringList items={effectiveQ.data.deny_view_names} />
              </dd>
              <dt>deny_artifact_paths</dt>
              <dd>
                <StringList items={effectiveQ.data.deny_artifact_paths} />
              </dd>
              <dt>deny_branch_names</dt>
              <dd>
                <StringList items={effectiveQ.data.deny_branch_names} />
              </dd>
            </dl>
          </div>

          {effectiveQ.data.notes && effectiveQ.data.notes.length > 0 && (
            <div className="card">
              <h2>Notes</h2>
              <ul style={{ margin: 0, paddingLeft: "1.2rem" }}>
                {effectiveQ.data.notes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}

      <div className="card">
        <h2>Pilot pilot overlay (draft → validate → apply)</h2>
        {overlayQ.isLoading && <p className="muted">Loading overlay…</p>}
        {overlayQ.isError && <ErrorBanner error={overlayQ.error} />}
        {overlayQ.isSuccess && !overlayQ.data.available && (
          <div className="banner warn" role="status">
            Plain overlay not available for edit
            {overlayQ.data.residual ? `: ${overlayQ.data.residual}` : "."}
            {overlayQ.data.notes?.length
              ? ` ${overlayQ.data.notes.join(" ")}`
              : ""}
          </div>
        )}
        {!canWrite && (
          <div className="banner warn" role="status">
            Role lacks <code>policy_write</code> (need{" "}
            <code>--admin-role policy_admin</code>). Validate/Apply disabled.
            Enterprise <code>force_read_only</code> can never be widened from
            this console.
          </div>
        )}

        <div className="banner warn" role="note" style={{ marginBottom: "0.75rem" }}>
          <strong>Subject rate residual (HOST-006 / HOST-008):</strong>{" "}
          <code>max_tools_per_minute</code> / <code>max_tools_burst</code>{" "}
          overlay knobs <strong>lower only</strong> under a live gateway serve
          via <code>SubjectRateLimiter.LowerRate</code> (never raise above the
          env bootstrap ceiling). Raising the bootstrap needs a serve restart
          with higher <code>JENKINS_MCP_SUBJECT_RATE_*</code>. Rate is
          process-local; multi-replica shared rate remains residual
          (HOST-008). Empty draft fields omit the overlay keys (no change).
        </div>

        <div className="form-grid">
          <label className="form-field">
            <span>force_read_only</span>
            <input
              type="checkbox"
              checked={draft.force_read_only}
              disabled={!canWrite}
              onChange={(e) =>
                setDraft((d) => ({ ...d, force_read_only: e.target.checked }))
              }
            />
            {errorsByField.get("force_read_only")?.map((m, i) => (
              <span key={i} className="field-error">
                {m}
              </span>
            ))}
          </label>

          <label className="form-field">
            <span>fleet_telemetry_force_off</span>
            <input
              type="checkbox"
              checked={Boolean(draft.fleet_telemetry_force_off)}
              disabled={!canWrite}
              onChange={(e) =>
                setDraft((d) => ({
                  ...d,
                  fleet_telemetry_force_off: e.target.checked,
                }))
              }
            />
            <span className="muted" style={{ fontSize: "0.85em" }}>
              MGR-002: when true, env cannot re-enable fleet telemetry (lower-only pin)
            </span>
            {errorsByField.get("fleet_telemetry_force_off")?.map((m, i) => (
              <span key={i} className="field-error">
                {m}
              </span>
            ))}
          </label>

          <label className="form-field">
            <span>mode</span>
            <select
              value={draft.mode || "pilot"}
              disabled={!canWrite}
              onChange={(e) =>
                setDraft((d) => ({ ...d, mode: e.target.value }))
              }
            >
              <option value="pilot">pilot</option>
              <option value="strict">strict</option>
            </select>
            {errorsByField.get("mode")?.map((m, i) => (
              <span key={i} className="field-error">
                {m}
              </span>
            ))}
          </label>

          <label className="form-field">
            <span>max_result_bytes</span>
            <input
              type="text"
              inputMode="numeric"
              value={maxBytesText}
              disabled={!canWrite}
              placeholder="optional positive int"
              onChange={(e) => setMaxBytesText(e.target.value)}
            />
            {errorsByField.get("max_result_bytes")?.map((m, i) => (
              <span key={i} className="field-error">
                {m}
              </span>
            ))}
          </label>

          <label className="form-field">
            <span>max_tools_per_minute</span>
            <input
              type="text"
              inputMode="numeric"
              value={maxToolsPerMinText}
              disabled={!canWrite}
              placeholder="optional positive int (lower only)"
              onChange={(e) => setMaxToolsPerMinText(e.target.value)}
            />
            {errorsByField.get("max_tools_per_minute")?.map((m, i) => (
              <span key={i} className="field-error">
                {m}
              </span>
            ))}
          </label>

          <label className="form-field">
            <span>max_tools_burst</span>
            <input
              type="text"
              inputMode="numeric"
              value={maxToolsBurstText}
              disabled={!canWrite}
              placeholder="optional positive int (lower only)"
              onChange={(e) => setMaxToolsBurstText(e.target.value)}
            />
            {errorsByField.get("max_tools_burst")?.map((m, i) => (
              <span key={i} className="field-error">
                {m}
              </span>
            ))}
          </label>

          {(
            [
              ["tools", "deny_tools"],
              ["jobs", "deny_job_prefixes"],
              ["nodes", "deny_node_names"],
              ["views", "deny_view_names"],
              ["artifacts", "deny_artifact_paths"],
              ["branches", "deny_branch_names"],
            ] as const
          ).map(([key, field]) => (
            <label key={field} className="form-field form-field-wide">
              <span>
                {field}{" "}
                <span className="muted">(one per line or comma-separated)</span>
              </span>
              <textarea
                rows={3}
                value={denyText[key]}
                disabled={!canWrite}
                onChange={(e) =>
                  setDenyText((d) => ({ ...d, [key]: e.target.value }))
                }
              />
              {errorsByField.get(field)?.map((m, i) => (
                <span key={i} className="field-error">
                  {m}
                </span>
              ))}
            </label>
          ))}
        </div>

        <div className="toolbar" style={{ marginTop: "0.75rem" }}>
          <button
            type="button"
            className="btn"
            disabled={!canWrite || validateMut.isPending}
            onClick={() => validateMut.mutate()}
          >
            {validateMut.isPending ? "Validating…" : "Validate"}
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canWrite || applyMut.isPending}
            onClick={() => setConfirmOpen(true)}
          >
            Apply
          </button>
          {statusMsg && (
            <span className="toolbar-meta muted" role="status">
              {statusMsg}
            </span>
          )}
        </div>

        {fieldErrors.length > 0 && (
          <div className="banner error" style={{ marginTop: "0.75rem" }}>
            <strong>Field errors</strong>
            <ul style={{ margin: "0.35rem 0 0", paddingLeft: "1.2rem" }}>
              {fieldErrors.map((e, i) => (
                <li key={i}>
                  <code>{e.field}</code>: {e.message}
                </li>
              ))}
            </ul>
          </div>
        )}

        {preview?.effectivePreview && (
          <div style={{ marginTop: "0.75rem" }}>
            <h3 style={{ fontSize: "0.95rem", margin: "0 0 0.5rem" }}>
              Effective preview (after validate)
            </h3>
            <pre className="json">
              {JSON.stringify(preview.effectivePreview, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {effectiveQ.isSuccess && (
        <div className="card">
          <h2>Raw effective JSON</h2>
          <pre className="json">
            {JSON.stringify(effectiveQ.data, null, 2)}
          </pre>
        </div>
      )}

      {confirmOpen && (
        <div
          className="modal-backdrop"
          role="presentation"
          onClick={() => !applyMut.isPending && setConfirmOpen(false)}
        >
          <div
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="policy-apply-title"
            onClick={(e) => e.stopPropagation()}
          >
            <h2 id="policy-apply-title">Apply pilot overlay?</h2>
            <p className="muted">
              Writes plain <code>overlay.json</code> (mode 0600) on the host.
              Does <strong>not</strong> sign. Cannot widen enterprise{" "}
              <code>force_read_only</code>. No private keys are sent.
            </p>
            <div className="toolbar">
              <button
                type="button"
                className="btn"
                disabled={applyMut.isPending}
                onClick={() => setConfirmOpen(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={applyMut.isPending}
                onClick={() => applyMut.mutate()}
              >
                {applyMut.isPending ? "Applying…" : "Confirm apply"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
