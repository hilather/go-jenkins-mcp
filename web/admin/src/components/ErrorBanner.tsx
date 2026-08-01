import { formatApiError } from "../api/client";

export function ErrorBanner({ error }: { error: unknown }) {
  const { code, message } = formatApiError(error);
  return (
    <div className="banner error" role="alert">
      <strong className="code">{code}</strong>
      {": "}
      {message}
    </div>
  );
}

export function Loading() {
  return <p className="loading">Loading…</p>;
}
