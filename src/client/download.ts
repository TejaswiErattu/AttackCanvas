/**
 * Offers text as a file download, entirely in the browser: a Blob URL on a temporary link.
 * Nothing is sent to a server. Not pure (it touches the document), so it is kept apart from
 * the builders in exportCsv.ts.
 */

/** A UTF-8 byte order mark, so a spreadsheet opens non-ASCII text in a CSV correctly. */
export const UTF8_BOM = "﻿";

export function downloadText(fileName: string, text: string, mime: string, bom = false): void {
  const blob = new Blob(bom ? [UTF8_BOM, text] : [text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  try {
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    link.rel = "noopener";
    document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    // Revoked on the next turn: some browsers start the download after click() returns.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
