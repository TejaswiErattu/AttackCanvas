/**
 * The "Coming soon" list shown in the app (ComingSoon.tsx) and in README.md. One source:
 * the wording is copied from docs/final-sprint-playbook.md, and the README section must
 * match it word for word (tests/roadmap.test.tsx checks both).
 */
export type RoadmapItem = { title: string; detail: string };

export const COMING_SOON: RoadmapItem[] = [
  {
    title: "Incremental scans",
    detail: "The first scan reads the whole repository; later scans re-check only changed files and components.",
  },
  {
    title: "Full scan or change scan",
    detail: "The user picks a complete analysis or a cheaper review of what changed.",
  },
  {
    title: "Scans triggered by Git activity",
    detail: "Automatic scans on merge to main, with optional scans per commit and per pull request.",
  },
  {
    title: "Targeted branch scans",
    detail: "Scans of non-main branches only when they touch identity, database, encryption or network code.",
  },
  {
    title: "Scoring external dependencies by access",
    detail: "Severity that reflects what data and access a third-party component has.",
  },
  {
    title: "One-click GitHub issues",
    detail: "Today the tool pre-fills the issue and you submit it; later it can create it directly with a scoped token.",
  },
  {
    title: "Shared finding history",
    detail: "Status and drift are saved in your browser today; later they sync across devices and teammates.",
  },
  {
    title: "More benchmark apps",
    detail: "OWASP Juice Shop and DVWA alongside NodeGoat and the seeded repositories.",
  },
  {
    title: "Local models for cheap steps",
    detail: "Classification and question drafting on a local model, keeping Claude for the heavy reasoning.",
  },
];
