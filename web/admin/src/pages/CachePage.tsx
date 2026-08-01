import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import {
  fetchCacheSummary,
  fetchMe,
  formatApiError,
  getProfileId,
  hasCacheDestructive,
  postCacheEvict,
  postCacheEvictPlan,
} from "../api/client";
import type { EvictionPlanResponse } from "../api/types";
import { ErrorBanner, Loading } from "../components/ErrorBanner";

const EVICT_TOKEN = "EVICT";

function formatBytes(n: number | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function PlanCard({
  title,
  plan,
}: {
  title: string;
  plan: EvictionPlanResponse;
}) {
  return (
    <div className="card">
      <h2>{title}</h2>
      <dl className="dl">
        <dt>needsEviction</dt>
        <dd>{plan.needsEviction ? "true" : "false"}</dd>
        <dt>dryRun</dt>
        <dd>{plan.dryRun ? "true" : "false"}</dd>
        <dt>applied</dt>
        <dd>{plan.applied ? "true" : "false"}</dd>
        <dt>bytesNeeded</dt>
        <dd>{formatBytes(plan.bytesNeeded)}</dd>
        <dt>totalReclaim</dt>
        <dd>{formatBytes(plan.totalReclaimBytes)}</dd>
        <dt>pinsSkipped</dt>
        <dd>{plan.pinsSkipped}</dd>
        {plan.evicted != null && (
          <>
            <dt>evicted</dt>
            <dd>{plan.evicted}</dd>
            <dt>reclaimed</dt>
            <dd>{formatBytes(plan.reclaimedBytes)}</dd>
          </>
        )}
      </dl>
      {!plan.candidates?.length ? (
        <p className="muted">No eviction candidates.</p>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th>kind</th>
              <th>id</th>
              <th>bytes</th>
              <th>reason</th>
            </tr>
          </thead>
          <tbody>
            {plan.candidates.map((c) => (
              <tr key={`${c.kind}-${c.id}`}>
                <td>{c.kind}</td>
                <td className="mono">{c.id}</td>
                <td>{formatBytes(c.bytes)}</td>
                <td>{c.reason || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function CachePage() {
  const profileId = getProfileId();
  const qc = useQueryClient();
  const [showEvictModal, setShowEvictModal] = useState(false);
  const [confirmDraft, setConfirmDraft] = useState("");
  const [confirmStep2, setConfirmStep2] = useState(false);

  const me = useQuery({
    queryKey: ["me"],
    queryFn: fetchMe,
    retry: 1,
    staleTime: 30_000,
  });
  const canDestructive = hasCacheDestructive(me.data);

  const cache = useQuery({
    queryKey: ["cache", profileId],
    queryFn: () => fetchCacheSummary(profileId),
    retry: 1,
  });

  const planMut = useMutation({
    mutationFn: () => postCacheEvictPlan(profileId, 0),
  });

  const evictMut = useMutation({
    mutationFn: () => postCacheEvict(profileId, EVICT_TOKEN, 0),
    onSuccess: () => {
      setShowEvictModal(false);
      setConfirmDraft("");
      setConfirmStep2(false);
      void qc.invalidateQueries({ queryKey: ["cache", profileId] });
    },
  });

  function openEvictModal() {
    setConfirmDraft("");
    setConfirmStep2(false);
    setShowEvictModal(true);
    evictMut.reset();
  }

  function onEvictSubmit(e: FormEvent) {
    e.preventDefault();
    if (!canDestructive) return;
    if (!confirmStep2) {
      if (confirmDraft !== EVICT_TOKEN) return;
      // Force re-type on step 2 (true double-confirm in the SPA).
      setConfirmDraft("");
      setConfirmStep2(true);
      return;
    }
    if (confirmDraft !== EVICT_TOKEN) return;
    evictMut.mutate();
  }

  const usage = cache.data?.usage;

  return (
    <>
      <h1 className="page-title">Cache</h1>
      <p className="page-sub">
        Quota and eviction for profile <code>{profileId}</code> (
        <code>GET /admin/v1/profiles/{"{id}"}/cache</code>). Pin list and full
        cache repair remain CLI residuals.
      </p>

      {cache.isLoading && <Loading />}
      {cache.isError && <ErrorBanner error={cache.error} />}

      {cache.isSuccess && (
        <div className="card">
          <h2>Usage / quota</h2>
          {!cache.data.available ? (
            <div className="banner warn" role="status">
              Store unavailable. {cache.data.residual || "No residual detail."}
            </div>
          ) : (
            <dl className="dl">
              <dt>needsEviction</dt>
              <dd>{cache.data.needsEviction ? "true" : "false"}</dd>
              <dt>pins</dt>
              <dd>{cache.data.pins ?? 0}</dd>
              <dt>total physical</dt>
              <dd>{formatBytes(usage?.total_physical_bytes)}</dd>
              <dt>L1 physical</dt>
              <dd>{formatBytes(usage?.l1_physical_bytes)}</dd>
              <dt>L2 physical</dt>
              <dd>{formatBytes(usage?.l2_physical_bytes)}</dd>
              <dt>generations / packs</dt>
              <dd>
                {usage?.generations ?? 0} / {usage?.packs ?? 0}
              </dd>
              <dt>quota</dt>
              <dd>{formatBytes(usage?.quota_bytes)}</dd>
              <dt>overQuota</dt>
              <dd>{usage?.over_quota ? "true" : "false"}</dd>
            </dl>
          )}
        </div>
      )}

      <div className="card">
        <h2>Eviction plan</h2>
        <p className="muted">
          Non-destructive dry-run (
          <code>POST .../cache/evict-plan</code>). Available to all console
          roles with <code>read</code>.
        </p>
        <div className="toolbar">
          <button
            type="button"
            className="btn btn-primary"
            disabled={planMut.isPending}
            onClick={() => planMut.mutate()}
          >
            {planMut.isPending ? "Planning…" : "Run eviction plan"}
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => void cache.refetch()}
          >
            Refresh usage
          </button>
        </div>
        {planMut.isError && <ErrorBanner error={planMut.error} />}
      </div>

      {planMut.isSuccess && planMut.data && (
        <PlanCard title="Plan result (dry-run)" plan={planMut.data} />
      )}

      <div className="card">
        <h2>Destructive evict</h2>
        <p className="muted">
          Requires process role <strong>operator</strong> (
          <code>cache_destructive</code>) and server-side body{" "}
          <code>{`{ "confirm": "EVICT" }`}</code>. SPA uses a double-confirm
          modal (type EVICT twice).
        </p>
        {!canDestructive && (
          <div className="banner warn" role="status">
            Destructive controls hidden: current role lacks{" "}
            <code>cache_destructive</code>.
            {me.isError
              ? ` (${formatApiError(me.error).message})`
              : me.data
                ? ` Role: ${me.data.role}`
                : ""}
          </div>
        )}
        {canDestructive && (
          <div className="toolbar">
            <button
              type="button"
              className="btn btn-danger"
              onClick={openEvictModal}
            >
              Evict cache…
            </button>
          </div>
        )}
        {evictMut.isError && <ErrorBanner error={evictMut.error} />}
        {evictMut.isSuccess && evictMut.data && (
          <PlanCard title="Evict result" plan={evictMut.data} />
        )}
      </div>

      {showEvictModal && canDestructive && (
        <div
          className="modal-backdrop"
          role="presentation"
          onClick={() => setShowEvictModal(false)}
        >
          <div
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="evict-title"
            onClick={(ev) => ev.stopPropagation()}
          >
            <h2 id="evict-title">Confirm cache eviction</h2>
            <p>
              This permanently reclaims unpinned cache objects for{" "}
              <code>{profileId}</code>. Type <strong>{EVICT_TOKEN}</strong> to
              continue
              {confirmStep2 ? " again to apply" : ""}.
            </p>
            <form onSubmit={onEvictSubmit}>
              <label htmlFor="evict-confirm">
                Confirm token {confirmStep2 ? "(step 2 of 2)" : "(step 1 of 2)"}
              </label>
              <input
                id="evict-confirm"
                className="modal-input"
                value={confirmDraft}
                onChange={(ev) => setConfirmDraft(ev.target.value)}
                autoComplete="off"
                spellCheck={false}
                placeholder={EVICT_TOKEN}
              />
              <div className="modal-actions">
                <button
                  type="button"
                  className="btn"
                  onClick={() => setShowEvictModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-danger"
                  disabled={
                    confirmDraft !== EVICT_TOKEN || evictMut.isPending
                  }
                >
                  {evictMut.isPending
                    ? "Evicting…"
                    : confirmStep2
                      ? "Apply eviction"
                      : "Continue"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
