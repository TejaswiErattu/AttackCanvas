# Session-cookie facts and threats.v2 prompt (a3118b6): evaluation report

## Change
Commit `a3118b6`:
- `src/server/detect/sessionCookies.ts` computes each session cookie's effective HttpOnly,
  Secure and SameSite, with library defaults applied (express-session and cookie-session;
  live code only; non-literal values are reported as "unknown").
- The threat batch shows these as a `## SESSION COOKIES` context block. It is not evidence,
  so no confidence score changes.
- `prompts/threats.v2.md` adds one rule: when a cookie is HttpOnly, do not claim that script
  reads or steals it; state what the script can do as the victim, or omit the threat.
  Plaintext capture is unaffected.

The run also includes `b956a3f` (evidence at the same file and line counts once).

## Why a run was needed
The change alters what the model is told, so saved results cannot be replayed. There was one
fresh run: NodeGoat@c5cb68a, level 2, demo profile, questions skipped, 2,400 s phase limit.
It took 1,174 s (21:20:44 -> 21:40:18 UTC): 25 calls, $4.07 at list prices, 136 threats,
37 visible. All 136 are labelled independently against the pinned source; three are marked
UNCERTAIN in notes (t18, t100, t133).

## Results

| run | threats | visible | recall | visible recall | unsupported | visible unsupported | evidence acc | script-reads-cookie claims (unsupported/total) |
|---|---|---|---|---|---|---|---|---|
| after-fix (corrected) | 109 | 11 | 12/19 | 4/19 | 23/109 | 3/11 | 87/111 | 6/7 |
| c8dd73f | 118 | 16 | 16/19 | 7/19 | 28/118 | 3/16 | 97/117 | 11/12 |
| 7a0fb27 | 98 | 35 | 13/19 | 8/19 | 23/98 | 10/35 | 92/102 | 6/7 |
| f64cfa8 | 89 | 24 | 14/19 | 7/19 | 25/89 | 4/24 | 93/105 | 5/5 |
| **a3118b6** | 136 | 37 | **17/19** | **10/19** | 32/136 | **4/37** | 127/146 | **0/0** |

The last column counts threats whose scenario has script read, steal or exfiltrate the
cookie, with no network-capture wording. It is a text heuristic over the model's scenarios,
used for evaluation only.

- **Targeted claims:** the cookie-theft-by-script claim did not occur in this run. The two
  scenarios that mention the cookie are t65, which captures it from plaintext traffic
  (valid), and t136, which states "the connect.sid cookie itself is HttpOnly, so the script
  acts as the victim".
- **Counterparts:** the /research echo, unsupported as f64cfa8 t12 (cookie theft), now
  appears as t129/t91/t101 claiming same-origin requests as the victim. All three are
  supported; t129 is visible at 0.47.
- **Recall:** first all-result recall of XSS-AUTOESCAPE-OFF (t18, t59 claim same-origin
  actions). SESSION-FIXATION and MISSING-SECURITY-HEADERS are recalled again; nothing recalled
  in f64cfa8 was lost.
- **Visible recall:** gained NOSQL-WHERE, PLAINTEXT-PASSWORDS, MISSING-SECURITY-HEADERS and
  MISSING-FUNCTION-AUTHZ. USER-ENUMERATION appears only below the cutoff this time (t11 at
  0.00, t95 at 0.20).
- **Remaining visible unsupported (4):**
  - t70: marked bypasses still need a click.
  - t73: marked 0.3.5 lacks the ReDoS regex.
  - t80: mongodb advisory preconditions fail.
  - t84: profile self-XSS and clickjacking of a logged-out frame.
  None involves cookie theft.

## Attribution limits
Each run generates a different threat set (136 threats here, 89 in f64cfa8), and this run
also carries `b956a3f`. Recall differences are not attributable to the prompt change alone.
The cookie-claim column is the change's direct target, and it went to zero, but that is
still one run.
