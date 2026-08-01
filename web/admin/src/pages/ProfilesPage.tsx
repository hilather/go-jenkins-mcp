import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  fetchProfile,
  fetchProfiles,
  fetchSecuritySelfCheck,
  getProfileId,
  hasCacheDestructive,
  postSupportBundle,
  setProfileId,
  formatApiError,
  fetchMe,
} from "../api/client";
import { ErrorBanner, Loading } from "../components/ErrorBanner";
import { useSearchParams } from "react-router-dom";

export function ProfilesPage() {
  const profileId = getProfileId();
  const [searchParams, setSearchParams] = useSearchParams();
  const qc = useQueryClient();

  const me = useQuery({
    queryKey: ["me"],
    queryFn: fetchMe,
    retry: 1,
    staleTime: 30_000,
  });
  const canOps = hasCacheDestructive(me.data);

  const list = useQuery({
    queryKey: ["profiles"],
    queryFn: fetchProfiles,
    retry: 1,
  });

  const detail = useQuery({
    queryKey: ["profile", profileId],
    queryFn: () => fetchProfile(profileId),
    retry: 1,
  });

  const selfCheck = useQuery({
    queryKey: ["security-selfcheck", profileId],
    queryFn: () => fetchSecuritySelfCheck(profileId),
    retry: 1,
    enabled: false,
  });

  const supportPreview = useMutation({
    mutationFn: () =>
      postSupportBundle(profileId, { preview: true, offline: true }),
  });
  const supportCreate = useMutation({
    mutationFn: () =>
      postSupportBundle(profileId, { preview: false, offline: true }),
  });

  function selectProfile(id: string) {
    setProfileId(id);
    const next = new URLSearchParams(searchParams);
    next.set("profile", id);
    setSearchParams(next, { replace: true });
    void qc.invalidateQueries({ queryKey: ["profile"] });
  }

  return (
    <>
      <h1 className="page-title">Profiles</h1>
      <p className="page-sub">
        Secret-free connection profiles (
        <code>GET /admin/v1/profiles</code>). Tokens and keyring material are
        never returned — only <code>hasCredential</code> presence.
      </p>

      {list.isLoading && <Loading />}
      {list.isError && <ErrorBanner error={list.error} />}

      {list.isSuccess && (
        <div className="card">
          <h2>All profiles</h2>
          {!list.data.profiles?.length ? (
            <p className="muted">No profiles found under XDG config.</p>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>id</th>
                  <th>host</th>
                  <th>auth</th>
                  <th>user</th>
                  <th>credential</th>
                  <th>RO</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.data.profiles.map((p) => (
                  <tr key={p.id}>
                    <td className="mono">{p.id}</td>
                    <td className="mono">{p.jenkinsHost || p.jenkinsURL}</td>
                    <td>{p.authMethod}</td>
                    <td className="mono">{p.username || "—"}</td>
                    <td>
                      <span
                        className={`tag ${p.hasCredential ? "ok" : "warn"}`}
                      >
                        {p.hasCredential ? "yes" : "no"}
                      </span>
                    </td>
                    <td>{p.readOnly ? "yes" : "no"}</td>
                    <td>
                      <button
                        type="button"
                        className="btn"
                        onClick={() => selectProfile(p.id)}
                      >
                        Select
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <div className="card">
        <h2>
          Detail · <code>{profileId}</code>
        </h2>
        {detail.isLoading && <Loading />}
        {detail.isError && <ErrorBanner error={detail.error} />}
        {detail.isSuccess && (
          <dl className="dl">
            <dt>id</dt>
            <dd>{detail.data.id}</dd>
            <dt>displayName</dt>
            <dd>{detail.data.displayName || "—"}</dd>
            <dt>jenkinsURL</dt>
            <dd>{detail.data.jenkinsURL}</dd>
            <dt>jenkinsHost</dt>
            <dd>{detail.data.jenkinsHost || "—"}</dd>
            <dt>authMethod</dt>
            <dd>{detail.data.authMethod}</dd>
            <dt>username</dt>
            <dd>{detail.data.username || "—"}</dd>
            <dt>hasCredential</dt>
            <dd>{detail.data.hasCredential ? "true" : "false"}</dd>
            <dt>readOnly</dt>
            <dd>{detail.data.readOnly ? "true" : "false"}</dd>
            <dt>cacheEncryption</dt>
            <dd>{detail.data.cacheEncryption ? "true" : "false"}</dd>
          </dl>
        )}
      </div>

      <div className="card">
        <h2>Security self-check</h2>
        <p className="muted">
          Offline canaries only (
          <code>GET /admin/v1/profiles/{"{id}"}/security-selfcheck</code>).
        </p>
        <div className="toolbar">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => void selfCheck.refetch()}
            disabled={selfCheck.isFetching}
          >
            {selfCheck.isFetching ? "Running…" : "Run self-check"}
          </button>
        </div>
        {selfCheck.isError && <ErrorBanner error={selfCheck.error} />}
        {selfCheck.isSuccess && selfCheck.data && (
          <>
            <p>
              Overall:{" "}
              <span className={`tag ${String(selfCheck.data.overall)}`}>
                {selfCheck.data.overall}
              </span>
            </p>
            <table className="data">
              <thead>
                <tr>
                  <th>name</th>
                  <th>status</th>
                  <th>message</th>
                </tr>
              </thead>
              <tbody>
                {(selfCheck.data.items ?? []).map((item, i) => (
                  <tr key={`${item.name ?? "item"}-${i}`}>
                    <td className="mono">{item.name}</td>
                    <td>
                      <span className={`tag ${String(item.status ?? "")}`}>
                        {item.status}
                      </span>
                    </td>
                    <td>{item.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>

      <div className="card">
        <h2>Support bundle</h2>
        <p className="muted">
          Operator only (<code>cache_destructive</code>). Preview lists
          categories; create writes a scrubbed zip under XDG cache and returns
          path + size (not file bytes).
        </p>
        {!canOps && (
          <div className="banner warn" role="status">
            Current role cannot create support bundles. Start{" "}
            <code>admin serve --admin-role operator</code>.
          </div>
        )}
        <div className="toolbar">
          <button
            type="button"
            className="btn"
            disabled={!canOps || supportPreview.isPending}
            onClick={() => supportPreview.mutate()}
          >
            Preview
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={!canOps || supportCreate.isPending}
            onClick={() => {
              if (
                !window.confirm(
                  "Create a privacy-scrubbed support bundle on disk? (operator action)",
                )
              ) {
                return;
              }
              supportCreate.mutate();
            }}
          >
            Create bundle
          </button>
        </div>
        {supportPreview.isError && (
          <ErrorBanner error={supportPreview.error} />
        )}
        {supportCreate.isError && <ErrorBanner error={supportCreate.error} />}
        {supportPreview.isSuccess && supportPreview.data && (
          <div className="banner ok" role="status">
            Preview path would be:{" "}
            <code>{supportPreview.data.outputPath || "—"}</code>
            <br />
            Included: {(supportPreview.data.included ?? []).join(", ")}
          </div>
        )}
        {supportCreate.isSuccess && supportCreate.data && (
          <div className="banner ok" role="status">
            Written: <code>{supportCreate.data.path}</code> (
            {supportCreate.data.bytes ?? 0} bytes)
          </div>
        )}
        {(supportPreview.isError || supportCreate.isError) && null}
        {me.isError && (
          <p className="muted">
            Role unknown: {formatApiError(me.error).message}
          </p>
        )}
      </div>
    </>
  );
}
