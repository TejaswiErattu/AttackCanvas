/** The small pill label that introduces a section, with a gold dot. */
export default function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface/70 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.14em] text-muted">
      <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-gold" />
      {children}
    </span>
  );
}
