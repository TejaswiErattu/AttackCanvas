# NodeGoat after-fix: AI-proposed labels for the 82 remaining rows

> **AI PROPOSALS, NOT HUMAN-VERIFIED LABELS.** Drafted by Claude in a single read-only pass. Nothing here has been written to `eval/labels/nodegoat-after-fix.csv`. Only rows or groups the human labeler explicitly approves get transferred.

- Result: `eval/results/nodegoat-after-fix.json` (109 threats); 27 rows already human-labelled; the 82 below are unlabelled.
- Rules applied, from `eval/review/pending-evaluation-requirements.md`: all 19 draft items kept; NG-INSECURE-SESSION-COOKIE bundled; NG-VULNERABLE-DEPS needs the specific marked advisory; NG-PLAINTEXT-HTTP only when the finding acknowledges deployment dependence (all proposed HTTP matches state 'no TLS termination' in their assumptions); a route citation counts when it locates a route relevant to the claim; a generic 'no validation library imported' gap does not; an advisory counts only if its preconditions hold in NodeGoat.
- Source checked at OWASP/NodeGoat@c5cb68a.

## 1. Uncertain or needs a human decision (24 rows)

| id | proposed match | sup | evid | decision needed |
|---|---|---|---|---|
| threat-20 | (blank) | y | 1/1 | XSS angle: autoescape is off, so a quote-breaking payload could make this stored XSS; decide whether that counts as NG-XSS-AUTOESCAPE-OFF. |
| threat-31 | NG-CSRF | y | 1/1 | Claim says 'no CSRF token field'; the field exists but is unverified. Decide whether that inaccuracy matters for supported. |
| threat-38 | (blank) | y | 1/2 | Is ev-deploy-3 (compose 'web' service line) close enough to the URI line to count? |
| threat-39 | (blank) | n | 1/1 | Evidence is accurate but supports only 'the 2.x driver is used', not the claimed attack. |
| threat-42 | (blank) | y | 0/1 | Default demo credentials are intended for a training app; decide whether a 'known credentials' threat is supported for NodeGoat. |
| threat-43 | (blank) | y | 0/1 | ev-deploy-4 relevance (mongo service rather than the web command that runs db-reset). |
| threat-47 | (blank) | y | 0/1 | Supported only as 'EOL base image'; the crash/RCE claim is generic. Decide y vs n. |
| threat-49 | (blank) | n | 1/1 | Partly true (unpinned tags) / partly unsupported (cache poisoning). Decide y vs n. |
| threat-50 | (blank) | n | 0/0 | CI-hardening judgement; depends on repository settings not in the repo. |
| threat-51 | (blank) | n | 0/0 | Depends on repository visibility settings and what the fixtures contain. |
| threat-55 | NG-OPEN-REDIRECT | n | 0/1 | Should an unsupported consequence claim still match NG-OPEN-REDIRECT? (Same situation as threat-63.) |
| threat-57 | (blank) | y | 1/1 | Mechanism differs from the claim's example; marked(object) failure not reproduced. |
| threat-62 | (blank) | y | 1/1 | The size detail is wrong; decide whether that makes it unsupported. |
| threat-73 | (blank) | n | 0/1 | Whether res.redirect(undefined) throws in express 4.16.4 was not verified; message-only disclosure may still occur. |
| threat-77 | (blank) | n | 2/2 | This is NodeGoat's own 'XSS in URL context' lesson, but in the pinned code the href uses firstName. Confirm against profile.html:70/78. |
| threat-83 | (blank) | y | 0/0 | Possibly NG-SSRF-RESEARCH; the plaintext-upstream framing is odd. |
| threat-84 | NG-SSRF-RESEARCH | y | 1/1 | Does the reflected-content (XSS) consequence count as NG-SSRF-RESEARCH? |
| threat-86 | (blank) | y | 1/1 | needle's built-in defaults (open timeout only) not verified against the pinned version. |
| threat-88 | NG-SSRF-RESEARCH | y | 1/1 | Same question as threat-84. |
| threat-90 | NG-SESSION-FIXATION | y | 1/2 | Is /logout relevant (session lifetime)? Logout behaviour not re-checked. |
| threat-92 | NG-INSECURE-SESSION-COOKIE | n | 0/1 | Match-but-unsupported, like threat-63. Confirm. |
| threat-98 | NG-SSRF-RESEARCH | y | 1/1 | Same question as threat-84. |
| threat-101 | NG-MISSING-SECURITY-HEADERS | y | 2/2 | Match NG-MISSING-SECURITY-HEADERS, or treat as a separate tutorial-specific claim? |
| threat-104 | NG-MISSING-SECURITY-HEADERS | y | 1/1 | Same question as threat-101; clickjacking depends on browser cookie rules. |

## 2. Summary by expected item (proposed rows only)

| expected item | proposed matching rows |
|---|---|
| NG-SSJS-EVAL | (none) |
| NG-NOSQL-WHERE | (none) |
| NG-LOG-INJECTION | (none) |
| NG-PLAINTEXT-PASSWORDS | t67, t109 |
| NG-USER-ENUMERATION | (none) |
| NG-WEAK-PASSWORD-POLICY | (none) |
| NG-SESSION-FIXATION | t90 |
| NG-INSECURE-SESSION-COOKIE | t92(n) |
| NG-XSS-AUTOESCAPE-OFF | (none) |
| NG-IDOR-ALLOCATIONS | t26, t28, t72 |
| NG-MISSING-SECURITY-HEADERS | t101, t104 |
| NG-PLAINTEXT-HTTP | t23, t37, t61, t81, t87, t100, t106 |
| NG-UNENCRYPTED-PII | t68, t75, t80 |
| NG-MISSING-FUNCTION-AUTHZ | t19, t24 |
| NG-CSRF | t22, t31, t35, t59, t79 |
| NG-OPEN-REDIRECT | t25, t27, t55(n), t71 |
| NG-SSRF-RESEARCH | t84, t85, t88, t97, t98 |
| NG-REDOS-ROUTING | t78, t82 |
| NG-VULNERABLE-DEPS | (none) |
| (blank: no expected item) | 45 rows |

## 3. Duplicate groups

- **Unauthenticated / unencrypted MongoDB link**: already labelled: threat-1, threat-17 (labelled). Proposed rows: t29, t30, t38, t41, t45, t56, t74, t91, t94, t96
- **Plaintext HTTP on browser flows (deployment-dependent)**: already labelled: threat-6, 9, 14 (labelled). Proposed rows: t23, t37, t61, t81, t87, t100, t106
- **CSRF**: already labelled: threat-10 (labelled). Proposed rows: t22, t31, t35, t59, t79
- **IDOR on /allocations**: already labelled: threat-5, 7, 15 (labelled). Proposed rows: t26, t28, t72
- **Open redirect on /learn**: already labelled: threat-12, 52, 54 (labelled). Proposed rows: t25, t27, t71, t55
- **Missing function authz on /benefits**: already labelled: none. Proposed rows: t19, t24
- **Plaintext password storage**: already labelled: threat-93 (labelled). Proposed rows: t67, t109
- **Unencrypted PII**: already labelled: none. Proposed rows: t68, t75, t80
- **ReDoS on bankRouting**: already labelled: none. Proposed rows: t78, t82
- **/research SSRF**: already labelled: none. Proposed rows: t85, t97
- **/research reflected body**: already labelled: none. Proposed rows: t84, t88, t98
- **/research unbounded outbound fetch**: already labelled: none. Proposed rows: t86, t89, t99
- **Tutorial pages leak admin credentials**: already labelled: none. Proposed rows: t103, t105
- **Tutorial pages missing headers**: already labelled: none. Proposed rows: t101, t104
- **db-reset wipes data on start**: already labelled: none. Proposed rows: t40, t43
- **Memo resource exhaustion**: already labelled: none. Proposed rows: t58, t62
- **Missing audit / attribution**: already labelled: threat-4 (labelled). Proposed rows: t21, t33, t44, t53, t64, t66, t95
- **CI workflow**: already labelled: none. Proposed rows: t49, t50, t51
- **Dependency advisories not applicable**: already labelled: threat-16, 65, 70 (labelled). Proposed rows: t39, t69

## 4. All 82 proposals

| id | conf | title | matchesExpected | supported | evidenceCorrect | reason |
|---|---|---|---|---|---|---|
| threat-19 | 0.20 | Any logged-in employee can view and rewrite every colleague's benefit  | NG-MISSING-FUNCTION-AUTHZ | y | 2/2 | /benefits GET+POST behind isLoggedIn only (isAdmin fix commented out); handler hard-codes isAdmin:true and takes userId from body. Both route lines show the missing guard. |
| threat-20 | 0.20 | Unvalidated benefitStartDate and userId written to the users collectio | (blank) | y | 1/1 | benefitStartDate and userId written unvalidated (benefits-dao.js:23). The <img onerror> example is inert inside value="..." unless it first breaks out with a quote. **[uncertain]** |
| threat-21 | 0.20 | Benefit changes are not attributable to the acting user | (blank) | y | 1/1 | benefits-dao logs only the literal "Updated benefits"; no actor, target or old value recorded. Route locates POST /benefits. |
| threat-22 | 0.00 | Cross-site request forgery on POST /benefits changes another employee' | NG-CSRF | y | 0/0 | csurf disabled; benefits form has no token. No citations. |
| threat-23 | 0.00 | Plain HTTP carries the session cookie and benefits form on the browser | NG-PLAINTEXT-HTTP | y | 0/0 | Assumptions state no TLS termination (deployment-dependent). Plain http listener; no Secure cookie flag. |
| threat-24 | 0.20 | Unvalidated userId in POST /benefits body lets any logged-in user targ | NG-MISSING-FUNCTION-AUTHZ | y | 1/1 | Duplicate of threat-19 (POST half). Route locates POST /benefits. |
| threat-25 | 0.01 | Open redirect on GET /learn steals session-bearing users from the auth | NG-OPEN-REDIRECT | y | 0/1 | res.redirect(req.query.url) with no allow-list. ev-gap-2 only shows no validation library (settled rule: not counted). |
| threat-26 | 0.00 | Any logged-in employee reads another employee's allocations by walking | NG-IDOR-ALLOCATIONS | y | 1/1 | req.params userId, no ownership check; ev-gap-1 identifies the missing ownership check. |
| threat-27 | 0.01 | Unvalidated redirect target on GET /learn reachable over the CI-exerci | NG-OPEN-REDIRECT | y | 0/1 | Duplicate open redirect. 'Accepts javascript: targets' is only click-dependent (browsers do not follow a javascript: Location). ev-gap-2 not counted. |
| threat-28 | 0.06 | CI drives /allocations/:userId with no ownership check, so the flow ex | NG-IDOR-ALLOCATIONS | y | 1/1 | Duplicate IDOR; CI framing is irrelevant to the flaw. ev-gap-1 correct. |
| threat-29 | 0.00 | Unauthenticated MongoDB endpoint lets any process on the network imper | (blank) | y | 0/0 | Duplicate of threat-1 (unauthenticated Mongo on compose network). 'Impersonate' unnecessary for an anonymous client. |
| threat-30 | 0.00 | Unencrypted MongoDB wire traffic between the Contributions Handler and | (blank) | y | 0/0 | No TLS on the Mongo URI; sniffing/in-flight rewrite requires a position on the container network. |
| threat-31 | 0.05 | Cross-site request forgery changes another user's contribution percent | NG-CSRF | y | 1/1 | No CSRF verification. Detail: contributions.html:91 does contain a hidden _csrf field, but it is empty and never checked. Route locates POST /contributions. **[uncertain]** |
| threat-33 | 0.05 | Contribution updates are not attributable because no audit record is w | (blank) | y | 1/1 | ContributionsDAO.update upserts and logs only 'Updated contributions'. Route locates POST /contributions. |
| threat-35 | 0.00 | Cross-site request forgery forces a victim's payroll contribution upda | NG-CSRF | y | 0/0 | Duplicate CSRF on /contributions. No citations. |
| threat-37 | 0.00 | Session cookie and contribution percentages exposed in transit on the  | NG-PLAINTEXT-HTTP | y | 0/0 | Assumptions state no TLS termination. No citations. |
| threat-38 | 0.20 | MongoDB connection string in docker-compose.yml uses no authentication | (blank) | y | 1/2 | Credential-free URI in docker-compose. ev-deploy-3 locates the web service that carries MONGODB_URI (counted); ev-datastore-1 only shows the mongodb dependency (not counted). **[uncertain]** |
| threat-39 | 0.20 | Outdated mongodb 2.x driver pinned in package.json | (blank) | n | 1/1 | No specific driver vulnerability named; 'reaches driver behaviour the 4.x line no longer exhibits' is unsupported. ev-datastore-1 accurately locates the dependency. **[uncertain]** |
| threat-40 | 0.05 | web container startup loop re-runs db-reset.js, allowing destructive r | (blank) | y | 1/1 | compose command: until nc && node artifacts/db-reset.js && npm start; if the app exits, the loop re-runs db-reset, which drops collections. ev-deploy-3 locates the web service. |
| threat-41 | 0.00 | Seeder and DAO traffic to MongoDB travels unauthenticated and unencryp | (blank) | y | 1/1 | Duplicate unauthenticated-Mongo claim (seeder flow). ev-deploy-4 locates the mongo service. |
| threat-42 | 0.20 | Seeder writes fixed default admin and user accounts with known credent | (blank) | y | 0/1 | db-reset.js seeds admin/Admin_123, user1/User1_123, user2/User2_123 in plaintext; the README publishes them. ev-deploy-4 (mongo service line) does not show the seeded credentials. **[uncertain]** |
| threat-43 | 0.20 | Startup seeder drops every collection, destroying live user data on ea | (blank) | y | 0/1 | Duplicate of threat-40: unconditional dropCollection on each container start (and Heroku postdeploy). ev-deploy-4 is the mongo service, not the web command. **[uncertain]** |
| threat-44 | 0.20 | Seeder leaves no attributable record of who reset and reseeded the dat | (blank) | y | 0/1 | db-reset logs to stdout only; npm run db:seed exists. ev-deploy-4 does not show the logging. |
| threat-45 | 0.05 | Unauthenticated MongoDB endpoint lets an attacker on the network starv | (blank) | y | 1/1 | Anonymous clients can open connections to the exposed mongo service; conditional on network access. ev-deploy-4 locates the mongo service. |
| threat-46 | 0.20 | web container publishes port 4000 on all host interfaces with no resou | (blank) | y | 1/1 | '4000:4000' binds all host interfaces; no resource limits. Local-dev compose; exhaustion is a degree question. ev-deploy-3 locates the web service. |
| threat-47 | 0.20 | Container image built on end-of-life node:12-alpine base carrying unpa | (blank) | y | 0/1 | FROM node:12-alpine (lines 1, 7) is end-of-life. Exploitation of a specific CVE is speculative. ev-deploy-5 points at Dockerfile:18 (EXPOSE), not the FROM lines. **[uncertain]** |
| threat-48 | 0.20 | Production hardening of the app directory is left commented out in the | (blank) | y | 0/1 | Dockerfile:15 hardening is commented out and COPY --chown=node gives the runtime user write access to app files; requires code execution in the container first. ev-deploy-5 (EXPOSE line) does not show line 15. |
| threat-49 | 0.20 | E2E workflow triggers on pull_request with unpinned third-party action | (blank) | n | 1/1 | Actions are pinned by mutable tag (true), but the fork-PR cache-poisoning path is unlikely: PR-scoped caches are not restored by base-branch runs. ev-deploy-1 locates the workflow. **[uncertain]** |
| threat-50 | 0.00 | CI workflow runs on pull_request from forks and executes repository-co | (blank) | n | 0/0 | Running a PR's npm scripts on an ephemeral runner is normal CI; fork PRs get a read-only token and no secrets, so the stated impact is overstated. **[uncertain]** |
| threat-51 | 0.00 | Cypress failure artifacts uploaded publicly may leak seeded applicatio | (blank) | n | 0/0 | Artifacts upload only on failure and only test/e2e/screenshots (with moved videos); the data is fictitious Cypress fixtures, and public artifacts need a GitHub login. **[uncertain]** |
| threat-53 | 0.20 | Redirect target reaching /learn is never logged, leaving phishing redi | (blank) | y | 1/1 | /learn handler logs nothing about the redirect target. Route locates GET /learn. |
| threat-55 | 0.00 | Session cookie disclosed to the redirect target of GET /learn | NG-OPEN-REDIRECT | n | 0/1 | Built on the real open redirect, but cookies are never sent to another origin and default Referrer-Policy leaks only the origin; the 'session cookie disclosed' title is not supported. ev-gap-2 not counted. **[uncertain]** |
| threat-56 | 0.00 | MongoDB wire traffic on the memo flow travels unauthenticated and unen | (blank) | y | 0/0 | Duplicate unauthenticated-Mongo claim (memo flow). |
| threat-57 | 0.20 | Memo insert accepts arbitrary non-string bodies straight into MongoDB | (blank) | y | 1/1 | Form payload memo[$ne]=1 is NOT nested with urlencoded extended:false, but bodyParser.json() accepts {"memo":{...}}, which is inserted as an object; marked(object) would likely throw and break /memos for everyone. 'Nunjucks' is wrong (the engine is Swig). Route locates POST /memos. **[uncertain]** |
| threat-58 | 0.00 | Unbounded memo listing over the memo flow exhausts memory and stalls t | (blank) | y | 0/0 | getAllMemos: unfiltered find().sort().toArray(); no index, pagination or size cap. Degree question. |
| threat-59 | 0.00 | Cross-site request forgery posting memos as a logged-in victim | NG-CSRF | y | 1/1 | CSRF on POST /memos; SameSite defaults may limit it. Route locates POST /memos. |
| threat-60 | 0.20 | Stored XSS injected through the POST /memos memo field and rendered as | (blank) | n | 1/1 | marked is configured with sanitize:true, which escapes raw HTML like <img onerror>; the session cookie is HttpOnly. No marked advisory named, so not NG-VULNERABLE-DEPS. Route locates POST /memos. |
| threat-61 | 0.05 | Memo text and session cookie exposed in transit on the POST /memos req | NG-PLAINTEXT-HTTP | y | 1/1 | Assumptions state no TLS termination. Route locates POST /memos. |
| threat-62 | 0.20 | Unbounded memo body allows storage exhaustion of the memos collection | (blank) | y | 1/1 | No memo length check or rate limit; but body-parser's default 100kb limit rejects the 'multi-megabyte' bodies described. Repeated sub-limit posts still grow the collection. Route locates POST /memos. **[uncertain]** |
| threat-64 | 0.20 | Memos are stored and displayed with no author identity or audit trail | (blank) | y | 1/1 | memos-dao insert stores {memo, timestamp} only. Route locates POST /memos. |
| threat-66 | 0.00 | No per-user attribution for writes to the memos collection | (blank) | y | 0/0 | Duplicate of threat-64. |
| threat-67 | 0.00 | Passwords stored in plaintext in the MongoDB users collection | NG-PLAINTEXT-PASSWORDS | y | 0/0 | user-dao.js:17-31 stores password as given; bcrypt commented out. |
| threat-68 | 0.00 | SSN, date of birth and bank details written to the users collection un | NG-UNENCRYPTED-PII | y | 0/0 | profile-dao.js crypto helpers commented out; ssn/dob/bank fields stored raw. |
| threat-69 | 0.15 | Vulnerable mongodb 2.2.36 driver allows denial of service against the  | (blank) | n | 0/1 | GHSA-mh5c needs an invalid collection name on a missing DB; NodeGoat uses fixed collection names, so request values cannot trigger it. ev-osv-2 accurate as a version fact but does not support the scenario. |
| threat-71 | 0.01 | Open redirect on GET /learn forwards authenticated users to attacker-c | NG-OPEN-REDIRECT | y | 0/1 | Duplicate open redirect. ev-gap-2 not counted. |
| threat-72 | 0.00 | Any authenticated user can read another user's retirement allocations  | NG-IDOR-ALLOCATIONS | y | 1/1 | Duplicate IDOR; getNextSequence gives sequential ids. ev-gap-1 correct. |
| threat-73 | 0.00 | Unhandled error stacks rendered to the browser by the global error han | (blank) | n | 0/1 | error.js renders {{error}}, i.e. the message string, not the stack or container paths. The /learn gap citation does not support an error-handler claim. **[uncertain]** |
| threat-74 | 0.00 | Profile writes to MongoDB cross the container boundary without TLS or  | (blank) | y | 0/0 | Duplicate unauthenticated/unencrypted Mongo (profile flow). |
| threat-75 | 0.00 | SSN, date of birth and bank details written to the users collection in | NG-UNENCRYPTED-PII | y | 0/0 | Duplicate of threat-68. |
| threat-76 | 0.20 | Unbounded profile field sizes let a user inflate the users collection  | (blank) | n | 1/1 | updateUser overwrites the same user document, so repeated posts cannot accumulate; body-parser's 100kb default rejects multi-megabyte bodies. Route locates POST /profile. |
| threat-77 | 0.20 | Stored XSS through the profile website field encoded for HTML but rend | (blank) | n | 2/2 | website is rendered only in <input value="{{website}}">, not in an anchor href (the href uses firstNameSafeString), so a javascript: URL does not execute. NodeGoat's comment is misleading. Both routes locate the profile flow. **[uncertain]** |
| threat-78 | 0.20 | ReDoS on POST /profile via the bankRouting field's nested quantifier r | NG-REDOS-ROUTING | y | 1/1 | /([0-9]+)+\#/ at profile.js:59 evaluated on raw bankRouting. Route locates POST /profile. |
| threat-79 | 0.00 | Cross-site request forgery overwrites a victim's SSN, address and bank | NG-CSRF | y | 1/1 | CSRF on POST /profile. Route locates POST /profile. |
| threat-80 | 0.20 | Profile fields stored unencrypted in the users collection after POST / | NG-UNENCRYPTED-PII | y | 1/1 | Duplicate of threat-68. Route locates POST /profile, where the fields are written. |
| threat-81 | 0.05 | SSN, date of birth and bank details submitted over cleartext HTTP on P | NG-PLAINTEXT-HTTP | y | 1/1 | Assumptions state no TLS termination. Route locates POST /profile. |
| threat-82 | 0.20 | Catastrophic regex backtracking on the bankRouting field stalls the No | NG-REDOS-ROUTING | y | 1/1 | Duplicate of threat-78. |
| threat-83 | 0.00 | Outbound research fetch accepts an attacker-chosen, possibly plaintext | (blank) | y | 0/0 | The attacker chooses the whole fetch URL, so response content can be spoofed; this is a facet of the SSRF. **[uncertain]** |
| threat-84 | 0.20 | Fetched remote HTML echoed into the response enables stored-free XSS a | NG-SSRF-RESEARCH | y | 1/1 | research.js writes the fetched body verbatim as text/html on the app origin; the key item explicitly includes 'echoes the body back'. Cookie theft is blocked by HttpOnly, but the assumption allows authenticated same-origin requests instead. Route locates GET /research. **[uncertain]** |
| threat-85 | 0.00 | Server-side request forgery via the url parameter on GET /research | NG-SSRF-RESEARCH | y | 1/1 | url + symbol fetched with needle, no allow-list; metadata example depends on the hosting environment. Route locates GET /research. |
| threat-86 | 0.05 | Unbounded outbound fetch on GET /research exhausts server connections | (blank) | y | 1/1 | needle.get without explicit timeouts or size limits; slow upstream can pin sockets. Route locates GET /research. **[uncertain]** |
| threat-87 | 0.00 | Credentials and session cookie on the /research request exposed if the | NG-PLAINTEXT-HTTP | y | 0/0 | Assumptions state no TLS termination; no Secure cookie flag. |
| threat-88 | 0.05 | Reflected untrusted remote content injected into the /research respons | NG-SSRF-RESEARCH | y | 1/1 | Duplicate of threat-84. **[uncertain]** |
| threat-89 | 0.20 | Server-side fetch on /research used to exhaust the Node process and am | (blank) | y | 1/1 | Duplicate of threat-86. |
| threat-90 | 0.05 | Admin authorisation depends only on a session userId lookup with no re | NG-SESSION-FIXATION | y | 1/2 | No req.session.regenerate at login (session.js:116); MemoryStore sessions have no expiry. ev-route-3 (/login, where rotation is missing) counted; ev-route-6 (/logout) is not the location of the flaw. **[uncertain]** |
| threat-91 | 0.00 | MongoDB reachable without authentication, permitting direct tampering  | (blank) | y | 0/0 | With anonymous Mongo access, setting isAdmin:true works because isAdminUserMiddleware reads the user document per request. Conditional on network access. |
| threat-92 | 0.05 | Session cookie secret is a hardcoded literal, allowing session forgery | NG-INSECURE-SESSION-COOKIE | n | 0/1 | The cookie secret is hard-coded (real, part of the bundled item), but express-session cookies carry a signed session id, not a userId; forging an admin session needs a valid server-side session. ev-route-3 does not locate the secret. **[uncertain]** |
| threat-94 | 0.00 | Plaintext passwords and SSN/bank fields traverse the MongoDB connectio | (blank) | y | 0/0 | No TLS on the Mongo URI; user-dao.js:45 insert is correct. |
| threat-95 | 0.20 | Login and signup outcomes are not audited, leaving credential attacks  | (blank) | y | 2/2 | Successful logins and signups are not recorded with identity or outcome. Detail: failed logins ARE console-logged with the username (session.js:64), so 'only redirect messages' is imprecise. Both routes locate the flows. |
| threat-96 | 0.00 | Loss of the single MongoDB instance halts all authentication and data  | (blank) | y | 0/0 | Single Mongo instance with no auth; drop or overload halts the app. Conditional on network access; generic availability. |
| threat-97 | 0.20 | Attacker-controlled url parameter on GET /research redirects the serve | NG-SSRF-RESEARCH | y | 1/1 | Duplicate of threat-85. |
| threat-98 | 0.20 | Remote page content fetched by /research is written unescaped into the | NG-SSRF-RESEARCH | y | 1/1 | Duplicate of threat-84. **[uncertain]** |
| threat-99 | 0.20 | Unbounded server-side fetch on /research allows resource exhaustion ag | (blank) | y | 1/1 | Duplicate of threat-86. |
| threat-100 | 0.00 | Session cookie observable on unauthenticated tutorial browsing over cl | NG-PLAINTEXT-HTTP | y | 0/0 | Assumptions state no TLS termination. Detail: layout.html has no /tutorial link (the claim says it does), but the cookie is still sent on tutorial requests. |
| threat-101 | 0.05 | Tutorial pages render third-party iframes and vendor assets without a  | NG-MISSING-SECURITY-HEADERS | y | 2/2 | No CSP on tutorial pages (true). environmentalScripts is only a development livereload snippet; attacker influence over those sources is hypothetical. Routes locate the tutorial pages. **[uncertain]** |
| threat-102 | 0.20 | Tutorial pages advertise exploitable routes and parameters of the live | (blank) | y | 2/2 | Tutorial pages are unauthenticated and describe the exploits (by design in NodeGoat). ssrf.html does not link /benefits (a7.html does). Both routes relevant (index and page). |
| threat-103 | 0.20 | Tutorial pages leak the built-in admin credentials to unauthenticated  | (blank) | y | 1/2 | a7.html:31 prints 'user: admin, password: Admin_123'; /tutorial is mounted without isLoggedIn. ev-route-20 serves a7 (counted); ev-route-19 is the /tutorial index (a1), not a7. |
| threat-104 | 0.20 | Tutorial page rendering accepts a template name derived from the route | NG-MISSING-SECURITY-HEADERS | y | 1/1 | Tutorial responses lack CSP / X-Frame-Options. Template names come from a fixed list (safe). Route-20 locates the page route. **[uncertain]** |
| threat-105 | 0.20 | Unauthenticated /tutorial pages disclose the application's default adm | (blank) | y | 1/2 | Duplicate of threat-103. |
| threat-106 | 0.05 | Login credentials submitted over plaintext HTTP can be captured or alt | NG-PLAINTEXT-HTTP | y | 1/1 | Assumptions state no TLS termination; login credentials cross in cleartext. Route locates POST /login. |
| threat-107 | 0.20 | Unthrottled POST /login flow allows credential stuffing and password b | (blank) | y | 1/1 | No attempt counter, lockout or delay in validateLogin. Route locates POST /login. |
| threat-108 | 0.20 | Unthrottled POST /signup flow permits mass account creation and storag | (blank) | y | 1/1 | Open signup with no CAPTCHA or rate limit. Route locates POST /signup. |
| threat-109 | 0.20 | Signup credentials stored in plaintext after crossing the POST /signup | NG-PLAINTEXT-PASSWORDS | y | 1/1 | Duplicate of threat-93/67. Route locates POST /signup. |
