/** Grouped operator rail (Status / Config / Ops). Loopback admin — not Jenkins UI. */

export type NavItem = {
  to: string;
  label: string;
  end?: boolean;
  /** Small residual badge (Metrics 15s poll). */
  badge?: string;
};

export type NavGroup = {
  id: "status" | "config" | "ops";
  label: string;
  items: NavItem[];
};

export const NAV_GROUPS: NavGroup[] = [
  {
    id: "status",
    label: "Status",
    items: [
      { to: "/", label: "Overview", end: true },
      { to: "/metrics", label: "Metrics", badge: "15s" },
      { to: "/doctor", label: "Doctor" },
    ],
  },
  {
    id: "config",
    label: "Config",
    items: [
      { to: "/profiles", label: "Profiles" },
      { to: "/policy", label: "Policy" },
      { to: "/access", label: "Access" },
    ],
  },
  {
    id: "ops",
    label: "Ops",
    items: [
      { to: "/audit", label: "Audit" },
      { to: "/cache", label: "Cache" },
    ],
  },
];

/** Flatten for tests / search-param wiring. */
export function flatNavItems(): NavItem[] {
  return NAV_GROUPS.flatMap((g) => g.items);
}

/** NavLink `to` must keep ?profile= (RR v6 pathname-only drops search). */
export function navTo(pathname: string, search: string): { pathname: string; search: string } {
  return { pathname, search };
}
