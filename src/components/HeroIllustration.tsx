/**
 * The home-page graphic: a repository turning into a connected architecture diagram with
 * a few highlighted risk paths.
 *
 * Purely illustrative. It carries no data from any analysis, names no real repository or
 * finding, and says so in its visible caption, so it cannot be mistaken for a result.
 * The SVG itself is aria-hidden; the caption is the accessible description. The dashed
 * risk paths animate only when the user has not asked for reduced motion (globals.css).
 */

type Box = { x: number; y: number; w: number; label: string };

const NODES: Box[] = [
  { x: 262, y: 36, w: 108, label: "Client" },
  { x: 392, y: 118, w: 104, label: "Auth" },
  { x: 262, y: 176, w: 108, label: "API" },
  { x: 392, y: 262, w: 104, label: "Queue" },
  { x: 262, y: 318, w: 108, label: "Database" },
  { x: 392, y: 384, w: 104, label: "Storage" },
];

const H = 36;

function center(label: string): { x: number; y: number } {
  const node = NODES.find((n) => n.label === label)!;
  return { x: node.x + node.w / 2, y: node.y + H / 2 };
}

function link(a: string, b: string): string {
  const p = center(a);
  const q = center(b);
  const midY = (p.y + q.y) / 2;
  return `M${p.x} ${p.y} C${p.x} ${midY} ${q.x} ${midY} ${q.x} ${q.y}`;
}

const LINKS: [string, string][] = [
  ["Client", "API"],
  ["Client", "Auth"],
  ["Auth", "API"],
  ["API", "Queue"],
  ["API", "Database"],
  ["Queue", "Storage"],
];

const RISK_LINKS: [string, string][] = [
  ["Client", "API"],
  ["API", "Database"],
];

const FILES = [
  { depth: 0, name: "src", dir: true },
  { depth: 1, name: "routes", dir: true },
  { depth: 2, name: "admin.ts", dir: false },
  { depth: 2, name: "notes.ts", dir: false },
  { depth: 1, name: "db", dir: true },
  { depth: 2, name: "queries.ts", dir: false },
  { depth: 1, name: "config.ts", dir: false },
  { depth: 0, name: "package.json", dir: false },
  { depth: 0, name: "Dockerfile", dir: false },
];

export default function HeroIllustration() {
  return (
    <figure className="relative">
      <div className="relative overflow-hidden rounded-3xl border border-line bg-surface/60 p-3 shadow-[0_30px_60px_-30px_rgba(42,84,217,0.45)] sm:p-4">
        <div className="bg-grid absolute inset-0 opacity-60" aria-hidden="true" />
        <svg
          viewBox="0 0 520 440"
          aria-hidden="true"
          focusable="false"
          className="relative block h-auto w-full"
        >
          <defs>
            <linearGradient id="hero-node" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="#fffcf4" />
              <stop offset="1" stopColor="#f3eddd" />
            </linearGradient>
            <linearGradient id="hero-flow" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0" stopColor="#2a54d9" stopOpacity="0" />
              <stop offset="1" stopColor="#2a54d9" stopOpacity="0.7" />
            </linearGradient>
          </defs>

          {/* The repository */}
          <rect x="16" y="36" width="190" height="368" rx="16" fill="#fffcf4" stroke="#e6dcc3" />
          <circle cx="36" cy="58" r="4" fill="#d3c6a5" />
          <circle cx="50" cy="58" r="4" fill="#d3c6a5" />
          <circle cx="64" cy="58" r="4" fill="#d3c6a5" />
          {FILES.map((file, index) => {
            const y = 96 + index * 32;
            const x = 34 + file.depth * 16;
            return (
              <g key={file.name}>
                <rect
                  x={x}
                  y={y - 8}
                  width="10"
                  height="10"
                  rx="2"
                  fill={file.dir ? "#2a54d9" : "none"}
                  fillOpacity={file.dir ? 0.35 : 0}
                  stroke="#2a54d9"
                  strokeOpacity="0.6"
                />
                <text
                  x={x + 18}
                  y={y + 1}
                  fontSize="12"
                  fontFamily="var(--font-geist-mono), monospace"
                  fill={file.dir ? "#4f5a74" : "#12213f"}
                >
                  {file.name}
                </text>
              </g>
            );
          })}

          {/* Repository to diagram */}
          <path d="M206 220 C230 220 236 194 262 194" stroke="url(#hero-flow)" strokeWidth="2" fill="none" />
          <path d="M206 250 C236 250 236 336 262 336" stroke="url(#hero-flow)" strokeWidth="2" fill="none" />
          <path d="M206 160 C232 160 236 54 262 54" stroke="url(#hero-flow)" strokeWidth="2" fill="none" />

          {/* Connections */}
          {LINKS.map(([a, b]) => (
            <path key={`${a}-${b}`} d={link(a, b)} stroke="#b9ab87" strokeWidth="1.5" fill="none" />
          ))}
          {RISK_LINKS.map(([a, b]) => (
            <path
              key={`risk-${a}-${b}`}
              d={link(a, b)}
              className="risk-path"
              stroke="#e0566b"
              strokeWidth="2.5"
              fill="none"
            />
          ))}

          {/* Components */}
          {NODES.map((node) => {
            const risky = node.label === "API" || node.label === "Database";
            return (
              <g key={node.label}>
                {risky ? (
                  <rect
                    className="pulse-ring"
                    x={node.x - 5}
                    y={node.y - 5}
                    width={node.w + 10}
                    height={H + 10}
                    rx="14"
                    fill="none"
                    stroke="#e0566b"
                    strokeOpacity="0.55"
                  />
                ) : null}
                <rect
                  x={node.x}
                  y={node.y}
                  width={node.w}
                  height={H}
                  rx="10"
                  fill="url(#hero-node)"
                  stroke={risky ? "#e0566b" : "#b9ab87"}
                />
                <circle cx={node.x + 16} cy={node.y + H / 2} r="4" fill={risky ? "#e0566b" : "#2a9d96"} />
                <text
                  x={node.x + 28}
                  y={node.y + H / 2 + 4}
                  fontSize="13"
                  fontFamily="var(--font-figtree), sans-serif"
                  fill="#12213f"
                >
                  {node.label}
                </text>
              </g>
            );
          })}

          {/* Trust boundary */}
          <rect
            x="248"
            y="152"
            width="262"
            height="266"
            rx="18"
            fill="none"
            stroke="#2a54d9"
            strokeOpacity="0.45"
            strokeDasharray="4 6"
          />
          <text x="258" y="432" fontSize="10" fill="#58627b" letterSpacing="1.5">
            TRUST BOUNDARY
          </text>
        </svg>
      </div>
      <figcaption className="mt-3 flex items-center gap-2 text-xs text-subtle">
        <span className="rounded-full border border-line px-2 py-0.5 font-medium uppercase tracking-wider text-muted">
          Illustration
        </span>
        Example shapes only. Your repository&apos;s real diagram appears after its analysis runs.
      </figcaption>
    </figure>
  );
}
