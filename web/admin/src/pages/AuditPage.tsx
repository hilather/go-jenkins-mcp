import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  fetchAudit,
  fetchAuditSettings,
  fetchMe,
  formatApiError,
  getProfileId,
  hasGatewayOps,
  putAuditSettings,
} from "../api/client";
import type { AuditEvent, AuditQuery } from "../api/types";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import { PageHeader } from "../components/PageHeader";
import { ResidualCallout } from "../components/ResidualCallout";
import {
  AUDIT_RESIDUAL_CAVEAT,
  AUDIT_RESIDUAL_DETAILS,
} from "../lib/leftoverResiduals";
import {
  AUDIT_LIMIT_OPTIONS,
  AUDIT_TYPE_HINTS,
  auditTypeFilterOptions,
  buildAuditExportPayload,
  datetimeLocalToRfc3339,
  filterEventsByExternalSubject,
  formatAuditSubjectCell,
  normalizeAuditLimit,
  olderBeforeCursor,
  presentAuditFields,
  type AuditLimit,
} from "../lib/auditQuery";
import { downloadJson } from "../lib/download";

interface AuditFilters {
  type: string;
  limit: AuditLimit;
  /** Free-text RFC3339 (used when datetime-local empty). */
  beforeText: string;
  /** datetime-local form value; takes precedence when set. */
  beforeLocal: string;
  /**
   * IdP subject label: sent as BFF `external_subject` (exact match).
   * Client-side exact filter remains residual fallback for older BFF.
   */
  externalSubject: string;
}

function defaultFilters(): AuditFilters {
  return {
    type: "",
    limit: 50,
    beforeText: "",
    beforeLocal: "",
    externalSubject: "",
  };
}

/** Resolve exclusive `before` for API from form fields. */
function resolveBeforeFilter(f: AuditFilters): string | undefined {
  if (f.beforeLocal.trim()) {
    return datetimeLocalToRfc3339(f.beforeLocal);
  }
  const t = f.beforeText.trim();
  return t || undefined;
}

function eventKey(ev: AuditEvent, index: number): string {
  return `${ev.time}|${ev.type}|${ev.requestId ?? ""}|${ev.tool ?? ""}|${index}`;
}

export function AuditPage() {
  const profileId = getProfileId();
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<AuditFilters>(defaultFilters);
  const [applied, setApplied] = useState<AuditFilters>(defaultFilters);
  /** When set, API `before` uses this load-older cursor (overrides form). */
  const [pageBefore, setPageBefore] = useState<string | undefined>(undefined);
  const [loaded, setLoaded] = useState<AuditEvent[]>([]);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [appendNext, setAppendNext] = useState(false);
  /** Local draft of type enable map (synced from settings GET). */
  const [enabledDraft, setEnabledDraft] = useState<Record<string, boolean>>({});
  const [settingsDirty, setSettingsDirty] = useState(false);
  const [settingsMsg, setSettingsMsg] = useState<string | null>(null);

  const formBefore = useMemo(() => resolveBeforeFilter(applied), [applied]);

  const query: AuditQuery = useMemo(
    () => ({
      limit: applied.limit,
      type: applied.type || undefined,
      before: pageBefore ?? formBefore,
      externalSubject: applied.externalSubject || undefined,
    }),
    [applied.limit, applied.type, pageBefore, formBefore, applied.externalSubject],
  );

  const meQ = useQuery({
    queryKey: ["me"],
    queryFn: () => fetchMe(),
    retry: 1,
    staleTime: 30_000,
  });
  const canEditSettings = hasGatewayOps(meQ.data);

  const settingsQ = useQuery({
    queryKey: ["audit-settings", profileId],
    queryFn: () => fetchAuditSettings(profileId),
    retry: 1,
  });

  useEffect(() => {
    if (!settingsQ.isSuccess || !settingsQ.data || settingsDirty) {
      return;
    }
    setEnabledDraft({ ...settingsQ.data.enabled });
  }, [settingsQ.dataUpdatedAt, settingsQ.isSuccess, settingsDirty, settingsQ.data]);

  /** Prefer draft when dirty; else server map so first paint matches GET (no flash). */
  const enabledView = useMemo(() => {
    if (settingsDirty) {
      return enabledDraft;
    }
    return settingsQ.data?.enabled ?? enabledDraft;
  }, [settingsDirty, enabledDraft, settingsQ.data?.enabled]);

  const saveSettingsMut = useMutation({
    mutationFn: () => putAuditSettings(enabledDraft, profileId),
    onSuccess: (data) => {
      setEnabledDraft({ ...data.enabled });
      setSettingsDirty(false);
      setSettingsMsg(
        "Saved. Serve reloads type_filter.json on mtime/size (no restart).",
      );
      void queryClient.invalidateQueries({ queryKey: ["audit-settings", profileId] });
    },
    onError: (err) => {
      setSettingsMsg(formatApiError(err).message);
    },
  });

  const typeFilterOptions = useMemo(
    () => auditTypeFilterOptions(settingsQ.data?.types),
    [settingsQ.data?.types],
  );

  const q = useQuery({
    queryKey: [
      "audit",
      profileId,
      query.limit ?? 50,
      query.type ?? "",
      query.before ?? "",
      query.externalSubject ?? "",
    ],
    queryFn: () => fetchAudit(profileId, query),
    retry: 1,
  });

  useEffect(() => {
    if (!q.isSuccess || !q.data) {
      return;
    }
    const page = q.data.events ?? [];
    setLoaded((prev) => {
      if (!appendNext) {
        return page;
      }
      const contentSeen = new Set(
        prev.map(
          (e) =>
            `${e.time}|${e.type}|${e.requestId ?? ""}|${e.tool ?? ""}|${e.reasonCode ?? ""}`,
        ),
      );
      const unique = page.filter(
        (e) =>
          !contentSeen.has(
            `${e.time}|${e.type}|${e.requestId ?? ""}|${e.tool ?? ""}|${e.reasonCode ?? ""}`,
          ),
      );
      return [...prev, ...unique];
    });
    setAppendNext(false);
    // appendNext is intentionally the value from the render that started the fetch.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.dataUpdatedAt, q.isSuccess]);

  useEffect(() => {
    if (q.isError) {
      setAppendNext(false);
    }
  }, [q.isError, q.errorUpdatedAt]);

  const applyFilters = (e?: { preventDefault(): void }) => {
    e?.preventDefault();
    setApplied({
      type: draft.type.trim(),
      limit: normalizeAuditLimit(draft.limit),
      beforeText: draft.beforeText.trim(),
      beforeLocal: draft.beforeLocal,
      externalSubject: draft.externalSubject.trim(),
    });
    setPageBefore(undefined);
    setAppendNext(false);
    setLoaded([]);
    setSelected(null);
  };

  const resetFilters = () => {
    const empty = defaultFilters();
    setDraft(empty);
    setApplied(empty);
    setPageBefore(undefined);
    setAppendNext(false);
    setLoaded([]);
    setSelected(null);
  };

  const loadOlder = () => {
    const cursor = olderBeforeCursor(loaded);
    if (!cursor) {
      return;
    }
    setAppendNext(true);
    setPageBefore(cursor);
  };

  /**
   * With current BFF, loaded events are already exact-filtered by external_subject.
   * Client exact filter remains residual for older BFFs that ignore the param.
   */
  const displayed = useMemo(
    () => filterEventsByExternalSubject(loaded, applied.externalSubject),
    [loaded, applied.externalSubject],
  );

  const exportLoaded = () => {
    const payload = buildAuditExportPayload(profileId, displayed, {
      truncated: Boolean(q.data?.truncated),
      filters: query,
    });
    downloadJson("audit-export.json", payload);
  };

  const canLoadOlder = Boolean(q.data?.truncated && olderBeforeCursor(loaded));
  const emptyMessage =
    "No audit events. Missing active file and rotated siblings returns an empty list (not 500). Events are privacy-preserving schema fields only.";

  const isSelected = (ev: AuditEvent) =>
    !!selected &&
    selected.time === ev.time &&
    selected.type === ev.type &&
    (selected.requestId ?? "") === (ev.requestId ?? "") &&
    (selected.tool ?? "") === (ev.tool ?? "");

  const toggleType = (type: string, on: boolean) => {
    setEnabledDraft((prev) => {
      const base = settingsDirty ? prev : { ...(settingsQ.data?.enabled ?? prev) };
      return { ...base, [type]: on };
    });
    setSettingsDirty(true);
    setSettingsMsg(null);
  };

  const setAllTypes = (on: boolean) => {
    const types = settingsQ.data?.types ?? Object.keys(enabledView);
    const next: Record<string, boolean> = { ...enabledView };
    for (const t of types) {
      next[t] = on;
    }
    setEnabledDraft(next);
    setSettingsDirty(true);
    setSettingsMsg(null);
  };

  const resetSettingsDraft = () => {
    if (settingsQ.data?.enabled) {
      setEnabledDraft({ ...settingsQ.data.enabled });
    }
    setSettingsDirty(false);
    setSettingsMsg(null);
  };

  return (
    <>
      <PageHeader title="Audit">
        Profile <code>{profileId}</code> · privacy-preserving event list
      </PageHeader>

      <ResidualCallout caveat={AUDIT_RESIDUAL_CAVEAT}>
        <p className="muted">{AUDIT_RESIDUAL_DETAILS}</p>
      </ResidualCallout>

      <section className="card filters-card" aria-labelledby="audit-settings-heading">
        <h2 id="audit-settings-heading">Event type settings</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Enable or disable which AUD-001 types the File sink persists for this
          profile (<code>audit/type_filter.json</code>). Requires{" "}
          <code>gateway_ops</code> (operator or policy_admin) to save. Catalog
          comes from <code>KnownEventTypes</code> — keep in sync when adding
          types.
        </p>
        {settingsQ.isLoading && <Loading />}
        {settingsQ.isError && <ErrorBanner error={settingsQ.error} />}
        {settingsQ.isSuccess && settingsQ.data && (
          <>
            <div className="audit-type-toggles">
              {(settingsQ.data.types.length
                ? settingsQ.data.types
                : Object.keys(enabledView)
              ).map((type) => {
                const checked = Boolean(enabledView[type]);
                const hint = AUDIT_TYPE_HINTS[type];
                return (
                  <label
                    key={type}
                    className="audit-type-toggle"
                    title={hint || type}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      disabled={!canEditSettings || saveSettingsMut.isPending}
                      onChange={(e) => toggleType(type, e.target.checked)}
                    />
                    <span className="mono">{type}</span>
                    {type === "tool_success" && (
                      <span className="muted audit-type-badge">high volume</span>
                    )}
                  </label>
                );
              })}
            </div>
            <div className="toolbar">
              <button
                type="button"
                className="btn btn-primary"
                disabled={
                  !canEditSettings || !settingsDirty || saveSettingsMut.isPending
                }
                onClick={() => saveSettingsMut.mutate()}
              >
                {saveSettingsMut.isPending ? "Saving…" : "Save type settings"}
              </button>
              <button
                type="button"
                className="btn"
                disabled={!canEditSettings || saveSettingsMut.isPending}
                onClick={() => setAllTypes(true)}
              >
                Enable all
              </button>
              <button
                type="button"
                className="btn"
                disabled={!canEditSettings || saveSettingsMut.isPending}
                onClick={() => setAllTypes(false)}
              >
                Disable all
              </button>
              <button
                type="button"
                className="btn"
                disabled={!settingsDirty || saveSettingsMut.isPending}
                onClick={resetSettingsDraft}
              >
                Reset draft
              </button>
              {!canEditSettings && (
                <span className="toolbar-meta muted">
                  Read-only: need <code>gateway_ops</code> to change settings
                  {meQ.data?.role ? ` (role: ${meQ.data.role})` : ""}
                </span>
              )}
              {settingsMsg && (
                <span className="toolbar-meta muted" role="status">
                  {settingsMsg}
                </span>
              )}
            </div>
            {settingsQ.data.residual ? (
              <p className="muted" style={{ fontSize: "0.8rem", marginBottom: 0 }}>
                Residual: {settingsQ.data.residual}
              </p>
            ) : null}
          </>
        )}
      </section>

      <form className="card filters-card" onSubmit={applyFilters}>
        <h2>Filters</h2>
        <div className="filters-grid">
          <label className="form-field">
            <span>type</span>
            <select
              className="input mono"
              value={draft.type}
              onChange={(e) =>
                setDraft((d) => ({ ...d, type: e.target.value }))
              }
            >
              {typeFilterOptions.map((opt) => (
                <option key={opt.value || "all"} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>
          <label className="form-field">
            <span>limit</span>
            <select
              className="input"
              value={draft.limit}
              onChange={(e) =>
                setDraft((d) => ({
                  ...d,
                  limit: normalizeAuditLimit(e.target.value),
                }))
              }
            >
              {AUDIT_LIMIT_OPTIONS.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
          <label className="form-field">
            <span>before (datetime-local)</span>
            <input
              type="datetime-local"
              className="input mono"
              value={draft.beforeLocal}
              onChange={(e) =>
                setDraft((d) => ({ ...d, beforeLocal: e.target.value }))
              }
            />
          </label>
          <label className="form-field form-field-wide">
            <span>before (RFC3339 text; used if local empty)</span>
            <input
              type="text"
              className="input mono"
              placeholder="2026-01-15T12:00:00Z"
              value={draft.beforeText}
              onChange={(e) =>
                setDraft((d) => ({ ...d, beforeText: e.target.value }))
              }
              autoComplete="off"
            />
          </label>
          <label className="form-field form-field-wide">
            <span>
              externalSubject (BFF exact match via external_subject; never a
              token)
            </span>
            <input
              type="text"
              className="input mono"
              placeholder="IdP subject label (exact)"
              value={draft.externalSubject}
              onChange={(e) =>
                setDraft((d) => ({ ...d, externalSubject: e.target.value }))
              }
              autoComplete="off"
            />
          </label>
        </div>
        <div className="toolbar">
          <button type="submit" className="btn btn-primary">
            Apply filters
          </button>
          <button type="button" className="btn" onClick={resetFilters}>
            Reset
          </button>
          <button
            type="button"
            className="btn"
            onClick={exportLoaded}
            disabled={displayed.length === 0}
          >
            Export loaded JSON
          </button>
          <span className="toolbar-meta muted">
            {displayed.length}
            {applied.externalSubject && loaded.length !== displayed.length
              ? ` of ${loaded.length}`
              : ""}{" "}
            loaded
            {q.data?.truncated ? " · truncated (more on server)" : ""}
            {pageBefore ? ` · cursor before=${pageBefore}` : ""}
            {applied.externalSubject
              ? ` · externalSubject=${applied.externalSubject}`
              : ""}
          </span>
        </div>
      </form>

      {q.isLoading && loaded.length === 0 && <Loading />}
      {q.isError && <ErrorBanner error={q.error} />}

      {(q.isSuccess || loaded.length > 0) && (
        <>
          {q.data?.truncated && (
            <div className="banner warn" role="status">
              Result truncated (more events exist beyond this page). Use{" "}
              <strong>Load older</strong> with the last event time as{" "}
              <code>before</code> cursor.
            </div>
          )}

          <div className="audit-layout">
            <div className="card audit-table-card">
              <h2>
                Events ({displayed.length}
                {q.data?.truncated ? ", page truncated" : ""}
                {applied.externalSubject && loaded.length !== displayed.length
                  ? `; filtered from ${loaded.length}`
                  : ""}
                )
              </h2>
              {!loaded.length ? (
                <EmptyState title="No audit events">{emptyMessage}</EmptyState>
              ) : !displayed.length ? (
                <EmptyState title="No matching events">
                  No events match externalSubject exact filter (BFF
                  external_subject; client residual for older BFF).
                </EmptyState>
              ) : (
                <div className="table-scroll">
                  <table className="data">
                    <thead>
                      <tr>
                        <th>time</th>
                        <th>type</th>
                        <th>decision</th>
                        <th>tool</th>
                        <th>reason</th>
                        <th>principal</th>
                        <th title="IdP subject label (gateway multi-user); never a token">
                          externalSubject
                        </th>
                        <th title="Opaque HashOpaque(tenant|subject|profile); never raw subject key">
                          subjectKeyHash
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {displayed.map((ev, i) => {
                        const active = isSelected(ev);
                        return (
                          <tr
                            key={eventKey(ev, i)}
                            className={active ? "row-active" : "row-clickable"}
                            onClick={() => setSelected(ev)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault();
                                setSelected(ev);
                              }
                            }}
                            tabIndex={0}
                            role="button"
                            aria-label={`Open audit event ${ev.type} at ${ev.time}`}
                          >
                            <td className="mono">{ev.time}</td>
                            <td className="mono">{ev.type}</td>
                            <td>{ev.decision || "—"}</td>
                            <td className="mono">{ev.tool || "—"}</td>
                            <td className="mono">{ev.reasonCode || "—"}</td>
                            <td className="mono">{ev.principalId || "—"}</td>
                            <td
                              className="mono muted"
                              title={ev.externalSubject || undefined}
                            >
                              {formatAuditSubjectCell(ev.externalSubject)}
                            </td>
                            <td
                              className="mono muted"
                              title={ev.subjectKeyHash || undefined}
                            >
                              {formatAuditSubjectCell(ev.subjectKeyHash)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="toolbar" style={{ marginTop: "0.75rem" }}>
                <button
                  type="button"
                  className="btn"
                  onClick={loadOlder}
                  disabled={!canLoadOlder || q.isFetching}
                >
                  {q.isFetching && appendNext ? "Loading…" : "Load older"}
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => void q.refetch()}
                  disabled={q.isFetching}
                >
                  Refresh page
                </button>
              </div>
            </div>

            <aside
              className={`card audit-drawer ${selected ? "" : "audit-drawer-empty"}`}
              aria-live="polite"
            >
              <h2>Event detail</h2>
              {!selected ? (
                <EmptyState title="No event selected">
                  Select a row to inspect schema fields.
                </EmptyState>
              ) : (
                <>
                  <dl className="dl">
                    {presentAuditFields(selected).map(({ key, value }) => (
                      <div key={key} className="dl-pair">
                        <dt>{key}</dt>
                        <dd className="mono">{value}</dd>
                      </div>
                    ))}
                  </dl>
                  <button
                    type="button"
                    className="btn"
                    style={{ marginTop: "0.75rem" }}
                    onClick={() => setSelected(null)}
                  >
                    Close
                  </button>
                </>
              )}
            </aside>
          </div>
        </>
      )}
    </>
  );
}
