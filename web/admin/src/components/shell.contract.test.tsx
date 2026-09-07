import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AdminApiError } from "../api/client";
import { ErrorBanner, Loading } from "./ErrorBanner";
import { PageHeader } from "./PageHeader";

/** Pages must use Loading(), ErrorBanner({ error }), PageHeader title+children. */
describe("admin SPA shell component contract", () => {
  it("Loading renders default copy", () => {
    const html = renderToStaticMarkup(<Loading />);
    expect(html).toContain("Loading…");
  });

  it("ErrorBanner formats { error }", () => {
    const html = renderToStaticMarkup(
      <ErrorBanner
        error={
          new AdminApiError(
            403,
            { code: "permission_denied", message: "admin token required" },
            "fallback",
          )
        }
      />,
    );
    expect(html).toContain("permission_denied");
    expect(html).toContain("admin token required");
  });

  it("PageHeader renders title and children subcopy", () => {
    const html = renderToStaticMarkup(
      <PageHeader title="Access">pilot break-glass only</PageHeader>,
    );
    expect(html).toContain("Access");
    expect(html).toContain("pilot break-glass only");
  });
});
