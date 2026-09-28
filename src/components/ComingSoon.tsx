import { COMING_SOON } from "@/shared/roadmap";
import SectionLabel from "@/components/SectionLabel";

/** The planned-but-not-built list (src/shared/roadmap.ts) as a compact card grid. */
export default function ComingSoon() {
  return (
    <section aria-labelledby="coming-soon-heading" className="border-t border-line/70">
      <div className="mx-auto w-full max-w-7xl px-4 py-12 sm:px-6">
        <SectionLabel>Roadmap</SectionLabel>
        <h2 id="coming-soon-heading" className="mt-4 font-display text-2xl font-semibold tracking-tight text-fg">
          Coming soon
        </h2>
        <ul className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {COMING_SOON.map((item) => (
            <li key={item.title} className="rounded-xl border border-line bg-surface/60 p-4">
              <h3 className="text-sm font-semibold text-fg">{item.title}</h3>
              <p className="mt-1 text-xs leading-relaxed text-muted">{item.detail}</p>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
