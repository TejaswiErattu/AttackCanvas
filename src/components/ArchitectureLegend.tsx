"use client";

/**
 * The key under the architecture diagram: one entry per component type that is actually
 * on the diagram (never the whole enum), in a fixed order, plus the two flow styles.
 */

import type { GraphNode } from "@/shared/viewModel";
import { COMPONENT_TYPE_TEXT, TypeIcon, shapeOf, typeText } from "@/components/ArchitectureNode";

const TYPE_ORDER = Object.keys(COMPONENT_TYPE_TEXT);

/** The distinct types of `nodes`, known types in enum order, unknown ones after, by name. */
export function legendTypes(nodes: readonly Pick<GraphNode, "type">[]): string[] {
  const present = [...new Set(nodes.map((node) => node.type as string))];
  const rank = (type: string) => {
    const index = TYPE_ORDER.indexOf(type);
    return index === -1 ? TYPE_ORDER.length : index;
  };
  return present.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
}

export default function ArchitectureLegend({ nodes }: { nodes: readonly GraphNode[] }) {
  const types = legendTypes(nodes);
  if (types.length === 0) return null;
  return (
    <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-subtle" aria-label="Diagram legend">
      <ul className="flex flex-wrap gap-x-3 gap-y-1.5" aria-label="Component types">
        {types.map((type) => (
          <li key={type} className="flex items-center gap-1.5">
            <TypeIcon shape={shapeOf(type)} className="text-muted" />
            {typeText(type)}
          </li>
        ))}
      </ul>
      <span className="flex items-center gap-1.5">
        <span aria-hidden="true" className="h-0 w-5 border-t-2 border-dashed border-boundary" />
        Crosses a trust boundary
      </span>
      <span className="flex items-center gap-1.5">
        <span aria-hidden="true" className="h-0.5 w-5 bg-flow" />
        Internal flow
      </span>
    </div>
  );
}
