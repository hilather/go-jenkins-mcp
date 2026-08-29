import { useEffect, useState, type FormEvent } from "react";
import { NavLink, Outlet, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  DEFAULT_PROFILE,
  fetchHealth,
  fetchMe,
  formatApiError,
  getAdminToken,
  getProfileId,
  setAdminToken,
  setProfileId,
} from "../api/client";
import {
  invalidateAfterTokenChange,
  isAdminAuthError,
  isBffUnreachable,
} from "../lib/adminErrors";
import { NAV_GROUPS, navTo } from "../lib/navGroups";
import { navLinkClassName } from "../lib/uiTheme";

export function Layout() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [profileDraft, setProfileDraft] = useState(() => getProfileId());
  const [tokenDraft, setTokenDraft] = useState(() =>
    getAdminToken() ? "••••••••" : "",
  );
  const [tokenDirty, setTokenDirty] = useState(false);

  useEffect(() => {
    const fromQuery = searchParams.get("profile")?.trim();
    if (fromQuery) {
      setProfileId(fromQuery);
      setProfileDraft(fromQuery);
    }
  }, [searchParams]);

  const healthQ = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    retry: 1,
  });
  const meQ = useQuery({
    queryKey: ["me"],
    queryFn: fetchMe,
    retry: 1,
  });

  function onProfileSubmit(e: FormEvent) {
    e.preventDefault();
    const next = profileDraft.trim() || DEFAULT_PROFILE;
    setProfileId(next);
    setProfileDraft(next);
    const nextParams = new URLSearchParams(searchParams);
    nextParams.set("profile", next);
    setSearchParams(nextParams, { replace: true });
  }

  function onTokenSubmit(e: FormEvent) {
    e.preventDefault();
    if (!tokenDirty && tokenDraft === "••••••••") {
      return;
    }
    const raw = tokenDraft.trim();
    invalidateAfterTokenChange(
      () => {
        void queryClient.invalidateQueries();
      },
      () => {
        if (!raw || raw === "••••••••") {
          setAdminToken(null);
          setTokenDraft("");
        } else {
          setAdminToken(raw);
          setTokenDraft("••••••••");
        }
        setTokenDirty(false);
      },
    );
  }

  const me = meQ.data ?? null;
  const meError = meQ.isError ? formatApiError(meQ.error) : null;
  const roleLabel = me?.role ?? (meError ? "—" : "…");
  const profileId = getProfileId();
  const healthErr = healthQ.error;
  const bffAuth = isAdminAuthError(healthErr);
  const bffDown = isBffUnreachable(healthErr);
  const bffOk = healthQ.isSuccess && !bffDown && !bffAuth;
  const bffLabel = bffOk
    ? "BFF ok"
    : bffAuth
      ? "BFF auth"
      : bffDown
        ? "BFF down"
        : healthQ.isLoading
          ? "BFF …"
          : "BFF";

  return (
    <div className="app-shell">
      <header className="app-topbar" role="banner">
        <div className="app-topbar-meta" aria-live="polite">
          <span className={`bff-dot${bffOk ? " ok" : bffAuth ? " auth" : ""}`} />
          {bffLabel}
          {healthQ.data?.version ? (
            <>
              {" · "}
              <code>{healthQ.data.version}</code>
            </>
          ) : null}
          {healthQ.data?.commit ? (
            <>
              {" · "}
              <code>{String(healthQ.data.commit).slice(0, 12)}</code>
            </>
          ) : null}
          {" · "}
          profile <code>{profileId}</code>
        </div>
      </header>
      <aside className="sidebar">
        <p className="mobile-nav-residual" role="note">
          Narrow layout residual: horizontal nav scroll — not a full mobile shell.
        </p>
        <div className="brand">
          jenkins-mcp operator console
          <span>jenkins-mcp</span>
          <span>Loopback admin · 127.0.0.1:8787</span>
        </div>
        {meError && (
          <div className="me-error" role="status">
            {meError.code}: {meError.message}
          </div>
        )}
        <nav className="nav-groups" aria-label="Primary">
          {NAV_GROUPS.map((group) => (
            <div key={group.id} className="nav-group">
              <p className="nav-group-label">{group.label}</p>
              <div className="nav">
                {group.items.map((item) => (
                  <NavLink
                    key={item.to}
                    to={navTo(item.to, searchParams.toString())}
                    end={item.end === true}
                    className={({ isActive }) => navLinkClassName(isActive)}
                  >
                    {item.label}
                    {item.badge ? (
                      <span className="nav-badge">{item.badge}</span>
                    ) : null}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="rail-footer">
          <div className="role-badge">
            <code>{profileId}</code>
            {" · "}
            role <strong>{roleLabel}</strong>
            {me?.tokenConfigured === false && (
              <span className="role-residual"> (no token residual)</span>
            )}
          </div>
          <form className="profile-box" onSubmit={onProfileSubmit}>
            <label htmlFor="profile-id">Profile</label>
            <input
              id="profile-id"
              name="profile"
              value={profileDraft}
              onChange={(ev) => setProfileDraft(ev.target.value)}
              spellCheck={false}
              autoComplete="off"
              title="Profile id (?profile= or localStorage jenkins-mcp.admin.profile)"
            />
          </form>
          <form className="profile-box token-box" onSubmit={onTokenSubmit}>
            <label htmlFor="admin-token">Admin token</label>
            <input
              id="admin-token"
              name="admin-token"
              type="password"
              value={tokenDraft}
              onChange={(ev) => {
                setTokenDraft(ev.target.value);
                setTokenDirty(true);
              }}
              spellCheck={false}
              autoComplete="off"
              placeholder="optional (localStorage)"
              title="Stored in localStorage jenkins-mcp.admin.token — pilot only; never logged"
            />
            <button type="submit" className="token-save">
              Save
            </button>
          </form>
          <p className="loopback-hint muted">
            Stored locally · sent as Bearer. <strong>Loopback only.</strong>
          </p>
        </div>
      </aside>
      <main className="main" id="main-content">
        <Outlet />
      </main>
    </div>
  );
}
