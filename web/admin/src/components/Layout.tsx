import { useEffect, useState, type FormEvent } from "react";
import { NavLink, Outlet, useSearchParams } from "react-router-dom";
import {
  DEFAULT_PROFILE,
  fetchMe,
  formatApiError,
  getAdminToken,
  getProfileId,
  setAdminToken,
  setProfileId,
} from "../api/client";
import type { MeResponse } from "../api/types";

const navItems: { to: string; label: string; end?: boolean }[] = [
  { to: "/", label: "Overview", end: true },
  { to: "/profiles", label: "Profiles" },
  { to: "/policy", label: "Policy" },
  { to: "/metrics", label: "Metrics" },
  { to: "/audit", label: "Audit" },
  { to: "/doctor", label: "Doctor" },
  { to: "/cache", label: "Cache" },
];

export function Layout() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [profileDraft, setProfileDraft] = useState(() => getProfileId());
  const [tokenDraft, setTokenDraft] = useState(() =>
    getAdminToken() ? "••••••••" : "",
  );
  const [tokenDirty, setTokenDirty] = useState(false);
  const [tokenEpoch, setTokenEpoch] = useState(0);
  const [me, setMe] = useState<MeResponse | null>(null);
  const [meError, setMeError] = useState<string | null>(null);

  // Persist ?profile= into localStorage when present.
  useEffect(() => {
    const fromQuery = searchParams.get("profile")?.trim();
    if (fromQuery) {
      setProfileId(fromQuery);
      setProfileDraft(fromQuery);
    }
  }, [searchParams]);

  // Load /admin/v1/me (role + residual). Re-fetch after token save/clear.
  useEffect(() => {
    let cancelled = false;
    fetchMe()
      .then((data) => {
        if (!cancelled) {
          setMe(data);
          setMeError(null);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setMe(null);
          const { code, message } = formatApiError(err);
          setMeError(`${code}: ${message}`);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [tokenEpoch]);

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
    if (!raw || raw === "••••••••") {
      setAdminToken(null);
      setTokenDraft("");
    } else {
      setAdminToken(raw);
      setTokenDraft("••••••••");
    }
    setTokenDirty(false);
    setTokenEpoch((n) => n + 1);
  }

  const roleLabel = me?.role ?? (meError ? "—" : "…");

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          jenkins-mcp
          <span>Admin console (v1 + ops)</span>
        </div>
        <div
          className="role-badge"
          title={
            me?.residual ??
            "Console role from admin serve --admin-role (UI-003)"
          }
        >
          Role: <strong>{roleLabel}</strong>
          {me?.tokenConfigured === false && (
            <span className="role-residual"> (no token residual)</span>
          )}
        </div>
        {meError && (
          <div className="me-error" role="status">
            {meError}
          </div>
        )}
        <nav className="nav" aria-label="Primary">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={{ pathname: item.to, search: searchParams.toString() }}
              end={item.end === true}
              className={({ isActive }) => (isActive ? "active" : undefined)}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
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
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
