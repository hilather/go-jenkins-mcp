import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAudit, getProfileId } from "../api/client";
import type { AuditEvent, AuditQuery } from "../api/types";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import {
  AUDIT_LIMIT_OPTIONS,
  AUDIT_TYPE_OPTIONS,
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
   * Client-side only filter on loaded events (BFF has no externalSubject query param).
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
  const [draft, setDraft] = useState<AuditFilters>(defaultFilters);
  const [applied, setApplied] = useState<AuditFilters>(defaultFilters);
  /** When set, API `before` uses this load-older cursor (overrides form). */
  const [pageBefore, setPageBefore] = useState<string | undefined>(undefined);
  const [loaded, setLoaded] = useState<AuditEvent[]>([]);
  const [selected, setSelected] = useState<AuditEvent | null>(null);
  const [appendNext, setAppendNext] = useState(false);

  const formBefore = useMemo(() => resolveBeforeFilter(applied), [applied]);

  const query: AuditQuery = useMemo(
    () => ({
      limit: applied.limit,
      type: applied.type || undefined,
      before: pageBefore ?? formBefore,
    }),
    [applied.limit, applied.type, pageBefore, formBefore],
  );

  const q = useQuery({
    queryKey: [
      "audit",
      profileId,
      query.limit ?? 50,
      query.type ?? "",
      query.before ?? "",
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

  /** Page-local view after optional client-side externalSubject filter. */
  const displayed = useMemo(
    () => filterEventsByExternalSubject(loaded, applied.externalSubject),
    [loaded, applied.externalSubject],
  );

  const exportLoaded = () => {
    const payload = buildAuditExportPayload(profileId, displayed, {
      truncated: Boolean(q.data?.truncated),
      filters: {
        ...query,
        externalSubject: applied.externalSubject || undefined,
      },
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

  return (
    <>
      <h1 className="page-title">Audit</h1>
      <p className="page-sub">
        Privacy-preserving audit tail for profile <code>{profileId}</code>{" "}
        (<code>GET /admin/v1/profiles/{"{id}"}/audit</code>). Cap limit ≤ 200.
        Same-host lite: BFF merges active <code>audit.jsonl</code> with rotated
        siblings (<code>audit.jsonl.N</code>). Multi-pod fleet aggregation remains
        residual. Multi-user correlation columns:{" "}
        <code>externalSubject</code> / <code>subjectKeyHash</code> (opaque hash
        only — never tokens). No live SSE tail in v1.
      </p>

      <form className="card filters-card" onSubmit={applyFilters}>
        <h2>Filters</h2>
        <div className="filters-grid">
          <label className="field">
            <span>type</span>
            <select
              className="input mono"
              value={draft.type}
              onChange={(e) =>
                setDraft((d) => ({ ...d, type: e.target.value }))
              }
            >
              {AUDIT_TYPE_OPTIONS.map((opt) => (
                <option key={opt.value || "all"} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
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
          <label className="field">
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
          <label className="field field-wide">
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
          <label className="field field-wide">
            <span>
              externalSubject (client filter on loaded page; BFF residual)
            </span>
            <input
              type="text"
              className="input mono"
              placeholder="IdP subject substring"
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
              ? ` · externalSubject≈${applied.externalSubject}`
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
                <p className="muted">{emptyMessage}</p>
              ) : !displayed.length ? (
                <p className="muted">
                  No events match externalSubject client filter on this page.
                </p>
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
                <p className="muted">Select a row to inspect schema fields.</p>
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
