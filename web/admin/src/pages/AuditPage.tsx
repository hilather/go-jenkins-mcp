import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { fetchAudit, getProfileId } from "../api/client";
import type { AuditEvent, AuditQuery } from "../api/types";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import {
  AUDIT_LIMIT_OPTIONS,
  buildAuditExportPayload,
  datetimeLocalToRfc3339,
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
}

function defaultFilters(): AuditFilters {
  return {
    type: "",
    limit: 50,
    beforeText: "",
    beforeLocal: "",
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

  const exportLoaded = () => {
    const payload = buildAuditExportPayload(profileId, loaded, {
      truncated: Boolean(q.data?.truncated),
      filters: query,
    });
    downloadJson("audit-export.json", payload);
  };

  const canLoadOlder = Boolean(q.data?.truncated && olderBeforeCursor(loaded));
  const emptyMessage =
    "No audit events. Missing audit file returns an empty list (not 500). Events are privacy-preserving schema fields only.";

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
        No live SSE tail in v1.
      </p>

      <form className="card filters-card" onSubmit={applyFilters}>
        <h2>Filters</h2>
        <div className="filters-grid">
          <label className="field">
            <span>type</span>
            <input
              type="text"
              className="input mono"
              placeholder="e.g. tool_deny"
              value={draft.type}
              onChange={(e) =>
                setDraft((d) => ({ ...d, type: e.target.value }))
              }
              autoComplete="off"
            />
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
            disabled={loaded.length === 0}
          >
            Export loaded JSON
          </button>
          <span className="toolbar-meta muted">
            {loaded.length} loaded
            {q.data?.truncated ? " · truncated (more on server)" : ""}
            {pageBefore ? ` · cursor before=${pageBefore}` : ""}
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
                Events ({loaded.length}
                {q.data?.truncated ? ", page truncated" : ""})
              </h2>
              {!loaded.length ? (
                <p className="muted">{emptyMessage}</p>
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
                      </tr>
                    </thead>
                    <tbody>
                      {loaded.map((ev, i) => {
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
