/**
 * The analysis page. A server component whose only job is to read the id out of the route
 * and hand it to the client view that does the polling.
 *
 * Nothing is fetched here: the analysis is in-memory, per-process and short-lived, so
 * rendering it on the server would only produce markup that is stale by the first poll.
 * Because the id lives in the URL, refreshing the page simply restarts polling against the
 * same job and picks the state back up.
 */

import AnalysisView from "@/components/AnalysisView";

export default async function AnalyzePage({ params }: PageProps<"/analyze/[id]">) {
  const { id } = await params;

  return (
    <main id="main" className="bg-glow flex-1">
      <div className="mx-auto w-full max-w-7xl px-4 py-10 sm:px-6 sm:py-12">
        <AnalysisView analysisId={id} />
      </div>
    </main>
  );
}
