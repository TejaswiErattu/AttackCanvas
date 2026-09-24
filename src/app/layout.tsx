import type { Metadata } from "next";
import Link from "next/link";
import { Bricolage_Grotesque, Figtree, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

/** The body face. */
const figtree = Figtree({
  variable: "--font-figtree",
  subsets: ["latin"],
});

/** The display face, for headings and large numbers. */
const bricolage = Bricolage_Grotesque({
  variable: "--font-bricolage",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AttackCanvas",
  description:
    "Threat-model a public GitHub repository: architecture, STRIDE threats mapped to OWASP Top 10:2025 and CWE, with the evidence behind each one.",
};

/** Concentric lens: teal rim, cobalt ring, gold centre. */
function LogoMark() {
  return (
    <svg viewBox="0 0 28 28" aria-hidden="true" className="h-7 w-7">
      <circle cx="14" cy="14" r="14" className="fill-teal" />
      <circle cx="14" cy="14" r="9.2" className="fill-surface" />
      <circle cx="14" cy="14" r="7.8" className="fill-mint" />
      <circle cx="14" cy="14" r="4.7" className="fill-surface" />
      <circle cx="14" cy="14" r="2.5" className="fill-gold" />
    </svg>
  );
}

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${figtree.variable} ${bricolage.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-full focus:bg-mint focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-ink"
        >
          Skip to content
        </a>
        <header className="sticky top-0 z-40 border-b border-line/70 bg-ink/85 backdrop-blur">
          <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-4 sm:px-6">
            <Link
              href="/"
              className="flex items-center gap-2.5 rounded-md font-display text-xl font-bold tracking-tight text-fg"
            >
              <LogoMark />
              AttackCanvas
            </Link>
            <p className="hidden text-xs text-subtle sm:block">
              Read-only analysis of public GitHub repositories
            </p>
          </div>
        </header>
        {children}
        <footer className="mt-auto border-t border-line/70">
          <div className="mx-auto flex w-full max-w-7xl flex-col gap-2 px-4 py-6 text-xs text-subtle sm:flex-row sm:items-center sm:justify-between sm:px-6">
            <p>AttackCanvas reads code; it never runs it. Findings are a starting point for review, not a verdict.</p>
            <p>STRIDE &middot; OWASP Top 10:2025 &middot; CWE</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
