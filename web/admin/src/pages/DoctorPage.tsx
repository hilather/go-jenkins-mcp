import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { fetchDoctor, getProfileId } from "../api/client";
import { ErrorBanner, Loading } from "../components/ErrorBanner";

function statusClass(status: string): string {
  const s = status.toLowerCase();
  if (s === "ok") return "ok";
  if (s === "warn") return "warn";
  if (s === "fail") return "fail";
  return "skip";
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
