import type { ReactNode } from "react";

/**
 * Residual voice: purple badge + one-line caveat + optional HOST-* details.
 * Never tokens, paths, or live GO.
 */
export function ResidualCallout({
  badge = "Residual",
  caveat,
  children,
  className,
}: {
  badge?: string;
  caveat: string;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`card residual-card residual-callout ${className ?? ""}`}>
      <h2>
        <span className="residual-badge">{badge}</span>
      </h2>
      <p className="residual-caveat muted">{caveat}</p>
      {children ? (
        <details className="residual-details">
          <summary>HOST-* details</summary>
          <div className="residual-details-body">{children}</div>
        </details>
      ) : null}
    </div>
  );
}
