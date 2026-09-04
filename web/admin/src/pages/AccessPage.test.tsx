import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AccessPage } from "./AccessPage";

/** First paint uses shared Loading (default "Loading…"); tsc gates prop names. */
describe("AccessPage", () => {
  it("renders the shared Loading shell on first paint", () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const html = renderToStaticMarkup(
      <QueryClientProvider client={qc}>
        <AccessPage />
      </QueryClientProvider>,
    );
    expect(html).toContain("Loading…");
  });
});
