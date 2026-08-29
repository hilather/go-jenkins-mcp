import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  fetchMe,
  fetchPolicyBindings,
  formatApiError,
  hasPolicyWrite,
  previewPolicyBindings,
  putPolicyBindings,
} from "../api/client";
import type { GroupBinding, UserBinding } from "../api/types";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { ResidualCallout } from "../components/ResidualCallout";
import {
  ACCESS_RESIDUAL_CAVEAT,
  ACCESS_RESIDUAL_DETAILS,
} from "../lib/leftoverResiduals";

/**
 * UI-011 Access: pilot/break-glass editor for POL-006 user/group deny bindings.
 * Multi-fleet SoT remains signed config (docs/fleet/multi-fleet-rollout.md).
 */
export function AccessPage() {
  const qc = useQueryClient();
  const meQ = useQuery({ queryKey: ["me"], queryFn: () => fetchMe() });
  const canWrite = hasPolicyWrite(meQ.data);
  const q = useQuery({
    queryKey: ["policy-bindings"],
    queryFn: fetchPolicyBindings,
  });

  const [usersText, setUsersText] = useState("");
  const [groupsText, setGroupsText] = useState("");
  const [seeded, setSeeded] = useState(false);
  const [previewUser, setPreviewUser] = useState("alice");
  const [previewGroups, setPreviewGroups] = useState("contractors");
  const [previewTool, setPreviewTool] = useState("jenkins_get_build_logs");
  const [previewJob, setPreviewJob] = useState("");
  const [previewResult, setPreviewResult] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (q.data && !seeded) {
      setUsersText(JSON.stringify(q.data.users ?? [], null, 2));
      setGroupsText(JSON.stringify(q.data.groups ?? [], null, 2));
      setSeeded(true);
    }
  }, [q.data, seeded]);

  const putMut = useMutation({
    mutationFn: async () => {
      const users = JSON.parse(usersText || "[]") as UserBinding[];
      const groups = JSON.parse(groupsText || "[]") as GroupBinding[];
      return putPolicyBindings({ users, groups });
    },
    onSuccess: async () => {
      setErr(null);
      setSeeded(false);
      await qc.invalidateQueries({ queryKey: ["policy-bindings"] });
    },
    onError: (e: unknown) => {
      const { code, message } = formatApiError(e);
      setErr(`${code}: ${message}`);
    },
  });

  const previewMut = useMutation({
    mutationFn: () =>
      previewPolicyBindings({
        jenkins_user_id: previewUser,
        groups: previewGroups
          .split(/[,\s]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        tool_name: previewTool,
        job_name: previewJob || undefined,
      }),
    onSuccess: (data) => {
      setPreviewResult(
        data.allowed
          ? `allowed (reason=${data.reason_code || "ok"})`
          : `DENIED (reason=${data.reason_code || "deny"})`,
      );
      setErr(null);
    },
    onError: (e: unknown) => {
      const { code, message } = formatApiError(e);
      setErr(`${code}: ${message}`);
    },
  });

  const data = q.data;

  return (
    <>
      <PageHeader title="Access">
        User &amp; group deny bindings (POL-006). Multi-fleet SoT is signed
        config — this page is pilot break-glass only.
      </PageHeader>

      {q.isLoading && <Loading />}
      {q.isError && <ErrorBanner error={q.error} />}
      {err ? <ErrorBanner error={new Error(err)} /> : null}

      {q.isSuccess && data ? (
        <>
          <ResidualCallout caveat={ACCESS_RESIDUAL_CAVEAT}>
            <p className="muted">{ACCESS_RESIDUAL_DETAILS}</p>
            <p className="muted">
              {data.fleet_sot ||
                "configuration/signed policy (MGR-001); SPA is pilot break-glass only"}
            </p>
            {data.residual ? <p className="muted">{data.residual}</p> : null}
            {data.notes?.length ? (
              <ul className="muted" style={{ margin: 0, paddingLeft: "1.2rem" }}>
                {data.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            ) : null}
          </ResidualCallout>

          <p className="muted" role="status">
            available={String(data.available)} · signature_state=
            {data.signature_state || "—"} · path_base={data.path_base || "—"}
          </p>

          <section className="card" aria-label="User bindings editor">
            <h2>subjects.users (JSON)</h2>
            <label className="form-field">
              <span>User bindings JSON</span>
              <textarea
                rows={10}
                value={usersText}
                onChange={(e) => setUsersText(e.target.value)}
                spellCheck={false}
                aria-label="User bindings JSON"
                disabled={!canWrite}
              />
            </label>
          </section>

          <section className="card" aria-label="Group bindings editor">
            <h2>subjects.groups (JSON)</h2>
            <label className="form-field">
              <span>Group bindings JSON</span>
              <textarea
                rows={10}
                value={groupsText}
                onChange={(e) => setGroupsText(e.target.value)}
                spellCheck={false}
                aria-label="Group bindings JSON"
                disabled={!canWrite}
              />
            </label>
          </section>

          <div className="toolbar">
            <button
              type="button"
              className="btn btn-primary"
              disabled={!canWrite || putMut.isPending}
              onClick={() => putMut.mutate()}
            >
              {putMut.isPending ? "Saving…" : "Save bindings (plain overlay)"}
            </button>
            {!canWrite ? (
              <span className="toolbar-meta muted">
                Requires policy_admin role to write.
              </span>
            ) : null}
          </div>

          <section className="card" aria-label="Effective preview">
            <h2>Effective preview</h2>
            <p className="muted">
              Dry-run deny-only evaluator for a hypothetical subject (not
              process authn).
            </p>
            <div className="form-grid">
              <label className="form-field">
                <span>jenkins_user_id</span>
                <input
                  type="text"
                  value={previewUser}
                  onChange={(e) => setPreviewUser(e.target.value)}
                />
              </label>
              <label className="form-field">
                <span>groups (comma-separated)</span>
                <input
                  type="text"
                  value={previewGroups}
                  onChange={(e) => setPreviewGroups(e.target.value)}
                />
              </label>
              <label className="form-field">
                <span>tool_name</span>
                <input
                  type="text"
                  value={previewTool}
                  onChange={(e) => setPreviewTool(e.target.value)}
                />
              </label>
              <label className="form-field">
                <span>job_name (optional)</span>
                <input
                  type="text"
                  value={previewJob}
                  onChange={(e) => setPreviewJob(e.target.value)}
                />
              </label>
            </div>
            <div className="toolbar">
              <button
                type="button"
                className="btn"
                disabled={previewMut.isPending}
                onClick={() => previewMut.mutate()}
              >
                Preview
              </button>
            </div>
            {previewResult ? (
              <p role="status" className="mono">
                {previewResult}
              </p>
            ) : null}
          </section>
        </>
      ) : null}
    </>
  );
}

export default AccessPage;
