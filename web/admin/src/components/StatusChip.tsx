import type { StatusChip as Chip } from "../lib/overviewHealth";

export function StatusChipRow({ chips }: { chips: Chip[] }) {
  if (!chips.length) {
    return null;
  }
  return (
    <ul className="status-chip-row" aria-label="Status summary">
      {chips.map((c) => (
        <li
          key={c.id}
          className={`status-chip tone-${c.tone}`}
          title={c.title}
        >
          <span className="status-chip-label">{c.label}</span>
          <span className="status-chip-value mono">{c.value}</span>
        </li>
      ))}
    </ul>
  );
}
