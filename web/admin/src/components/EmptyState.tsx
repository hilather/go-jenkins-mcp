import type { ReactNode } from "react";

/** Shared empty-state block (UI-POLISH-004). */
export function EmptyState({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty-state" role="status">
      <p className="empty-state-title">{title}</p>
      {children ? <div className="empty-state-body muted">{children}</div> : null}
    </div>
  );
}
