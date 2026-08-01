import type { ReactNode } from "react";

/**
 * Consistent page title + subcopy (UI-POLISH-001).
 */
export function PageHeader({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <header className="page-header">
      <h1 className="page-title">{title}</h1>
      {children ? <div className="page-sub">{children}</div> : null}
    </header>
  );
}
