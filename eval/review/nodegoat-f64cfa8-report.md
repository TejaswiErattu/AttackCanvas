# CWE-scoped gap floor (f64cfa8): evaluation report

## Change
CLAUDE.md rule 2: the 0.40 gap floor applies only when every CWE the threat claims is among
the CWEs asserted by its cited control gaps; a threat with no CWE gets no floor.
Commit `f64cfa8`: `src/shared/confidence.ts`, `src/server/scoring/index.ts`, CLAUDE.md, the
scoring README, and tests (`tests/gapFloorCwe.test.ts`, with helpers updated in
`tests/scoring.test.ts` and `tests/confidence.test.ts`).

## Isolated effect: replay of saved results (identical threat sets)
Gap certainties and CWEs come from the current detectors on NodeGoat@c5cb68a. The old-rule
replay reproduces every stored confidence (109/109, 118/118, 98/98), and the new-rule replay
of the fresh run reproduces its stored values (89/89).

| run | rows changed | visible | visible recall | visible unsupported |
|---|---|---|---|---|
| after-fix | 0 | 11 -> 11 | 4/19 -> 4/19 | 3 -> 3 |
| c8dd73f | 0 | 16 -> 16 | 7/19 -> 7/19 | 3 -> 3 |
| 7a0fb27 | 9 (t2, t10, t12, t55, t69, t75, t78, t83: n; t95: y) | 35 -> 26 | 8/19 -> 8/19 | 10 -> 2 |
| f64cfa8 (old-rule counterfactual) | 8 (t2, t6, t16, t59, t65, t70, t83: n; t25: y) | 32 -> 24 | 7/19 -> 7/19 | 11 -> 4 |

Rows still floored in f64cfa8: t3, t8, t15, t58, t69, t75, t77, all CWE-352 CSRF, all
supported.

## Fresh run f64cfa8 (all 89 labelled)
Settings: NodeGoat@c5cb68a, level 2, demo profile, questions skipped, 2,400 s phase limit.
Run: 20:41:35 -> 20:55:04 UTC (809 s), 18 calls, $3.16, 89 threats, 24 visible.
Four labels were initially marked uncertain (t36, t44, t66, t85); see "Uncertain labels reviewed" below. None changed.

| run | threats | visible | recall | visible recall | unsupported | visible unsupported | evidence acc | visible evidence acc |
|---|---|---|---|---|---|---|---|---|
| after-fix (original) | 109 | 11 | 13/19 | 4/19 | 22/109 | 3/11 | 87/111 | 24/29 |
| after-fix (corrected) | 109 | 11 | 12/19 | 4/19 | 23/109 | 3/11 | 87/111 | 24/29 |
| c8dd73f | 118 | 16 | 16/19 | 7/19 | 28/118 | 3/16 | 97/117 | 34/40 |
| 7a0fb27 | 98 | 35 | 13/19 | 8/19 | 23/98 | 10/35 | 92/102 | 50/52 |
| f64cfa8 | 89 | 24 | 14/19 | 7/19 | 25/89 | 4/24 | 93/105 | 44/49 |

- f64cfa8 recalls LOG-INJECTION (t42, t57), UNENCRYPTED-PII (t26) and MISSING-FUNCTION-AUTHZ (t68)
  and shows USER-ENUMERATION on the dashboard (t56, 0.55).
- It misses WEAK-PASSWORD-POLICY, SESSION-FIXATION, XSS-AUTOESCAPE-OFF,
  MISSING-SECURITY-HEADERS and VULNERABLE-DEPS.
- Its 4 visible unsupported rows (t12, t46, t49, t79) rest on Semgrep or OSV evidence, not on
  the floor.
- Differences between runs reflect different generated threat sets, not the rule alone; only
  the replay rows above isolate the rule.

## Uncertain labels reviewed (no label or metric changes)
Checked against NodeGoat@c5cb68a; the two threshold cases were tested with express 4.16.4.

| row | label | decision |
|---|---|---|
| t36 | (blank), y, 0/1 | Kept. `COPY --chown=node` (Dockerfile:13) plus `USER node` (line 17) leaves the app files writable by the runtime user, and the hardening line 15 is commented out. `.dockerignore` lists no `.env` (NodeGoat has none, and the claim is hedged). The cited EXPOSE line does not locate this. |
| t44 | NG-NOSQL-WHERE, y, 1/1 | Kept. The mechanism is JavaScript injection into `$where`, which is real (semgrep-1). Its example `0 \|\| true` is inert: it stays inside the quotes. As with earlier rows, a wrong example with a correct mechanism stays supported. |
| t66 | NG-NOSQL-WHERE, n, 1/1 | Kept. `threshold[$gt]=` is stringified to `'[object Object]'` inside the `$where` string, so the operator-object mechanism it describes does not work. It never describes quote-breaking JavaScript. |
| t85 | (blank), y, 1/1 | Kept. Signup does reveal existing names (session.js:213) and is unthrottled. NG-USER-ENUMERATION is the login form's distinct errors, a different mechanism, so it stays unmatched. |
