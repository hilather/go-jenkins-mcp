import { act, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserRouter, NavLink } from "react-router-dom";
import { App } from "./App";

// createRoot + act outside @testing-library.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT =
  true;

let root: Root | undefined;
let host: HTMLDivElement | undefined;

/** Pages fetch on mount. Fail closed so routing asserts do not need BFF payloads. */
function stubAdminFetch(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: false,
      status: 503,
      statusText: "unavailable",
      json: async () => ({ code: "unavailable", message: "offline" }),
    })),
  );
}

async function mount(node: ReactElement): Promise<HTMLDivElement> {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  await act(async () => {
    root!.render(node);
  });
  return host;
}

afterEach(async () => {
  if (root) {
    const current = root;
    root = undefined;
    await act(async () => {
      current.unmount();
    });
  }
  host?.remove();
  host = undefined;
  vi.unstubAllGlobals();
  window.history.pushState({}, "", "/");
});

describe("App routing", () => {
  it("sends an unknown splat URL to /", async () => {
    stubAdminFetch();
    window.history.pushState({}, "", "/not-a-page");
    await mount(<App />);
    expect(window.location.pathname).toBe("/");
  });

  it("keeps ?profile= on nav links", async () => {
    stubAdminFetch();
    window.history.pushState({}, "", "/?profile=corp");
    const el = await mount(<App />);
    const profiles = el.querySelector('a[href^="/profiles"]');
    expect(profiles).not.toBeNull();
    const url = new URL(
      profiles?.getAttribute("href") ?? "",
      window.location.origin,
    );
    expect(url.pathname).toBe("/profiles");
    expect(url.searchParams.get("profile")).toBe("corp");
  });

  it("resolves a backslash NavLink target as an in-app path", async () => {
    // GHSA-wrjc-x8rr-h8h6: browsers parse "\" as "/", so href "/\evil.example"
    // is the protocol-relative URL "//evil.example". 6.30.6 emits that href.
    window.history.pushState({}, "", "/");
    const el = await mount(
      <BrowserRouter>
        <NavLink to={"\\evil.example"}>probe</NavLink>
      </BrowserRouter>,
    );
    const href = el.querySelector("a")?.getAttribute("href") ?? "";
    expect(href).toBe("/evil.example");
    expect(href).toMatch(/^\//);
    expect(href).not.toMatch(/^\/\//);
    expect(href).not.toMatch(/^https?:/);
    expect(href).not.toContain("\\");
    expect(new URL(href, window.location.origin).origin).toBe(
      window.location.origin,
    );
  });
});
