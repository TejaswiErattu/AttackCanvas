# NodeGoat evaluation: review pack

> **Not labels.** Prepared by Claude from `eval/results` and the draft `eval/expected/nodegoat.yaml` with keyword and evidence heuristics. Candidate groupings are suggestions to speed up review; nothing here is human-verified. The scored CSV columns are blank and no accuracy has been calculated.

- **before** = `eval/baselines/nodegoat-before-fix/result.json`: 86 threats, AttackCanvas 3700d90.
- **after** = `eval/results/nodegoat-after-fix.json`: 109 threats, after d2ec8b7 + d21360d. It predates the Semgrep/windowing commit 7f7211d.
- Both: OWASP/NodeGoat@c5cb68a, demo profile, all questions skipped.

Legend: `✓` = visible on the dashboard (confidence ≥ 0.25). *route line* = evidence that only says the route exists, not the flaw. *gap* = a detector control gap.

## 1. Per expected threat: candidate generated threats

### NG-SSJS-EVAL

> Server-side JavaScript injection. The contributions handler passes the preTax, afterTax and roth request fields straight to eval(), so a request can run arbitrary code on the server.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t41 | 0.70 ✓ | critical | Server-side JavaScript injection via eval() of contribution fields on PO | routes/index.js:52 route line (POST /contributions); routes/contributions.js:32 semgrep eval-user-input; routes/contributions.js:33 semgrep eval-user-input; routes/contributions.js:34 semgrep eval-user-input |
| before | t62 | 0.00 | high | CSRF on POST /contributions lets an attacker's page drive the eval() sin | routes/contributions.js:32 semgrep eval-user-input |
| before | t63 | 0.70 ✓ | critical | Server-side JavaScript injection via POST /contributions preTax/afterTax | routes/index.js:52 route line (POST /contributions); routes/contributions.js:32 semgrep eval-user-input; routes/contributions.js:33 semgrep eval-user-input; routes/contributions.js:34 semgrep eval-user-input |
| before | t81 | 0.00 | critical | Unvalidated contribution values reach eval() and then the contributions  | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t32 | 0.70 ✓ | critical | Server-side JavaScript injection via preTax/afterTax/roth on POST /contr | routes/index.js:52 route line (POST /contributions); routes/contributions.js:32 semgrep eval-user-input; routes/contributions.js:33 semgrep eval-user-input; routes/contributions.js:34 semgrep eval-user-input |
| after | t34 | 0.55 ✓ | high | Denial of service by evaluating an infinite loop in the contributions fo | routes/index.js:52 route line (POST /contributions); routes/contributions.js:32 semgrep eval-user-input |
| after | t35 | 0.00 | high | Cross-site request forgery forces a victim's payroll contribution update | none (assumptions only) |
| after | t36 | 0.70 ✓ | critical | Server-side JavaScript injection via preTax/afterTax/roth on POST /contr | routes/index.js:52 route line (POST /contributions); routes/contributions.js:32 semgrep eval-user-input; routes/contributions.js:33 semgrep eval-user-input; routes/contributions.js:34 semgrep eval-user-input |

### NG-NOSQL-WHERE

> NoSQL injection. The allocations DAO interpolates the unsanitised `threshold` query parameter into a MongoDB $where JavaScript expression, allowing data exposure or DoS (e.g. while(true){}).

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t12 | 0.00 | high | Unvalidated userId passed into DAO query filters allows NoSQL operator i | none (assumptions only) |
| before | t56 | 0.32 ✓ | high | Unvalidated threshold query parameter on GET /allocations/:userId reache | routes/index.js:70 gap input_validation_missing (GET /learn); routes/index.js:63 route line (GET /allocations/:userId) |
| after | t2 | 0.20 | medium | Unvalidated threshold query value flows into the allocations MongoDB loo | routes/index.js:63 route line (GET /allocations/:userId) |
| after | t8 | 0.20 | high | Unvalidated threshold query parameter reaches the allocations Mongo quer | routes/index.js:63 route line (GET /allocations/:userId) |

### NG-LOG-INJECTION

> Log injection / log forging. The failed-login path writes the raw userName to console.log without stripping CR/LF.

_No candidate found in either run. Check §2 before concluding it is missed._

### NG-PLAINTEXT-PASSWORDS

> Passwords are stored in plaintext and compared with ===. The bcrypt hashing is commented out.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t9 | 0.00 | high | DAO-to-MongoDB traffic carries SSN, bank details and plaintext passwords | none (assumptions only) |
| before | t11 | 0.00 | critical | UserDAO stores registration passwords in plaintext in the users collecti | none (assumptions only) |
| before | t16 | 0.00 | high | Seed script writes plaintext credentials and PII to MongoDB over an unau | none (assumptions only) |
| before | t20 | 0.00 | high | Seeded user documents carry passwords that the seed flow never hashes | none (assumptions only) |
| before | t48 | 0.20 | critical | Signup stores passwords in plaintext in the users collection | routes/index.js:38 route line (POST /signup) |
| before | t86 | 0.01 | critical | Plaintext passwords travel from the signup handler into UserDAO and are  | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t67 | 0.00 | critical | Passwords stored in plaintext in the MongoDB users collection | none (assumptions only) |
| after | t93 | 0.35 ✓ | critical | Signup stores user passwords in plaintext in the users collection | routes/index.js:34 route line (POST /login); routes/index.js:38 route line (POST /signup) |
| after | t94 | 0.00 | high | Plaintext passwords and SSN/bank fields traverse the MongoDB connection  | none (assumptions only) |
| after | t109 | 0.20 | critical | Signup credentials stored in plaintext after crossing the POST /signup f | routes/index.js:38 route line (POST /signup) |

### NG-USER-ENUMERATION

> The login form returns distinct "Invalid username" and "Invalid password" errors, which lets an attacker enumerate valid accounts.

_No candidate found in either run. Check §2 before concluding it is missed._

### NG-WEAK-PASSWORD-POLICY

> Signup accepts any password of 1 to 20 characters. The stronger password regex is commented out.

_No candidate found in either run. Check §2 before concluding it is missed._

### NG-SESSION-FIXATION

> The session id is not regenerated on login (no req.session.regenerate), so a pre-login session id stays valid after authentication.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t2 | 0.00 | high | Session fixation and unbounded session lifetime on the app-render-to-use | none (assumptions only) |
| after | t10 | 0.05 | high | Session fixation and forged state via the in-process auth check with CSR | routes/index.js:44 route line (GET /dashboard) |

### NG-INSECURE-SESSION-COOKIE

> The session cookie has no httpOnly, no secure flag and no maxAge. The app uses the default connect.sid name and a hard-coded cookie secret from config/env/all.js.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t47 | 0.00 | critical | Hard-coded session cookie secret allows forging of session cookies | none (assumptions only) |
| before | t84 | 0.40 ✓ | high | Session-to-DAO admin lookup trusts a session userId with no session hard | routes/index.js:48 gap authn_missing (POST /profile); routes/index.js:67 gap authn_missing (POST /memos) |
| after | t9 | 0.00 | critical | Session cookie forgery and hijacking because the session/auth check trus | routes/index.js:44 route line (GET /dashboard) |
| after | t92 | 0.05 | critical | Session cookie secret is a hardcoded literal, allowing session forgery a | routes/index.js:34 route line (POST /login) |

### NG-XSS-AUTOESCAPE-OFF

> Reflected or stored XSS. Swig autoescape is disabled globally, so user-controlled values (e.g. profile firstName rendered into an input value and an href in profile.html) are emitted unescaped.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| after | t77 | 0.20 | high | Stored XSS through the profile website field encoded for HTML but render | routes/index.js:47 route line (GET /profile); routes/index.js:48 route line (POST /profile) |

### NG-IDOR-ALLOCATIONS

> Insecure direct object reference. /allocations/:userId takes the user id from the URL instead of the session, so any logged-in user can read another user's allocations.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t45 | 0.05 | critical | Insecure direct object reference on GET /allocations/:userId exposes oth | routes/index.js:63 route line (GET /allocations/:userId) |
| before | t57 | 0.05 | critical | Insecure direct object reference: any logged-in user reads another emplo | routes/index.js:63 route line (GET /allocations/:userId) |
| before | t82 | 0.00 | high | URL-supplied userId flows to AllocationsDAO, exposing other users' alloc | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t5 | 0.66 ✓ | critical | IDOR on GET /allocations/:userId exposes other users' allocation records | routes/index.js:63 gap authz_missing (GET /allocations/:userId); routes/index.js:63 route line (GET /allocations/:userId) |
| after | t7 | 0.66 ✓ | critical | Insecure direct object reference on GET /allocations/:userId exposes oth | routes/index.js:63 gap authz_missing (GET /allocations/:userId); routes/index.js:63 route line (GET /allocations/:userId) |
| after | t15 | 0.00 | critical | Another user's allocations rendered back to any logged-in caller via GET | routes/index.js:63 gap authz_missing (GET /allocations/:userId) |
| after | t26 | 0.00 | critical | Any logged-in employee reads another employee's allocations by walking / | routes/index.js:63 gap authz_missing (GET /allocations/:userId) |
| after | t72 | 0.00 | high | Any authenticated user can read another user's retirement allocations vi | routes/index.js:63 gap authz_missing (GET /allocations/:userId) |

### NG-MISSING-SECURITY-HEADERS

> Security misconfiguration. Helmet is not applied (no frameguard, CSP, HSTS, nosniff or no-cache) and x-powered-by is not disabled. All of it is commented out.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t3 | 0.00 | medium | No security response headers on rendered HTML enables clickjacking and u | none (assumptions only) |
| before | t79 | 0.20 | medium | Tutorial pages rendered without a Content-Security-Policy, weakening con | routes/tutorial.js:8 route line (GET /tutorial); routes/tutorial.js:31 route line (GET /tutorial/${page}) |
| after | t13 | 0.00 | high | Missing security response headers on rendered Swig pages allow clickjack | none (assumptions only) |
| after | t101 | 0.05 | medium | Tutorial pages render third-party iframes and vendor assets without a Co | routes/tutorial.js:8 route line (GET /tutorial); routes/tutorial.js:31 route line (GET /tutorial/${page}) |
| after | t104 | 0.20 | low | Tutorial page rendering accepts a template name derived from the route p | routes/tutorial.js:31 route line (GET /tutorial/${page}) |

### NG-PLAINTEXT-HTTP

> The server listens over plain HTTP only. The HTTPS server is commented out, so credentials and session cookies travel in cleartext.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t1 | 0.00 | high | Session cookie and rendered PII carried over plaintext HTTP to the brows | none (assumptions only) |
| before | t6 | 0.00 | medium | CI drives the app over plain HTTP, exposing session cookies and PII on t | none (assumptions only) |
| before | t29 | 0.20 | high | Session cookie theft over plaintext HTTP lets an attacker impersonate an | routes/index.js:34 route line (POST /login) |
| before | t55 | 0.20 | high | Session cookie for GET /allocations/:userId travels in cleartext across  | routes/index.js:63 route line (GET /allocations/:userId) |
| before | t59 | 0.00 | high | Session cookie and benefits form data sent over plaintext HTTP | none (assumptions only) |
| before | t65 | 0.20 | high | Credentials posted to /login travel over plain HTTP and can be read on t | routes/index.js:34 route line (POST /login) |
| before | t68 | 0.00 | high | POST /memos travels over plain HTTP, exposing the session cookie to netw | none (assumptions only) |
| before | t72 | 0.00 | high | POST /profile carries SSN and bank account numbers in clear text over HT | none (assumptions only) |
| before | t74 | 0.20 | high | Signup credentials submitted over plaintext HTTP to POST /signup | routes/index.js:38 route line (POST /signup) |
| before | t78 | 0.20 | high | Public tutorial pages served over plaintext HTTP allow response injectio | routes/tutorial.js:8 route line (GET /tutorial); routes/tutorial.js:31 route line (GET /tutorial/${page}) |
| after | t6 | 0.00 | high | Credentials and session cookie on the allocations request can be read on | none (assumptions only) |
| after | t9 | 0.00 | critical | Session cookie forgery and hijacking because the session/auth check trus | routes/index.js:44 route line (GET /dashboard) |
| after | t14 | 0.00 | critical | Unencrypted HTTP delivery of rendered pages exposes the session cookie a | none (assumptions only) |
| after | t23 | 0.00 | critical | Plain HTTP carries the session cookie and benefits form on the browser-t | none (assumptions only) |
| after | t37 | 0.00 | high | Session cookie and contribution percentages exposed in transit on the PO | none (assumptions only) |
| after | t61 | 0.05 | medium | Memo text and session cookie exposed in transit on the POST /memos reque | routes/index.js:67 route line (POST /memos) |
| after | t81 | 0.05 | critical | SSN, date of birth and bank details submitted over cleartext HTTP on POS | routes/index.js:48 route line (POST /profile) |
| after | t87 | 0.00 | high | Credentials and session cookie on the /research request exposed if the f | none (assumptions only) |
| after | t100 | 0.00 | high | Session cookie observable on unauthenticated tutorial browsing over clea | none (assumptions only) |
| after | t106 | 0.05 | critical | Login credentials submitted over plaintext HTTP can be captured or alter | routes/index.js:34 route line (POST /login) |

### NG-UNENCRYPTED-PII

> SSN and DOB from the profile are stored unencrypted in MongoDB. The AES encrypt and decrypt helpers are commented out.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t9 | 0.00 | high | DAO-to-MongoDB traffic carries SSN, bank details and plaintext passwords | none (assumptions only) |
| before | t14 | 0.00 | high | ProfileDAO writes SSN, DOB and bank routing details to MongoDB unencrypt | none (assumptions only) |
| before | t71 | 0.00 | high | CSRF on POST /profile lets an attacker overwrite a victim's SSN and bank | none (assumptions only) |
| before | t72 | 0.00 | high | POST /profile carries SSN and bank account numbers in clear text over HT | none (assumptions only) |
| after | t68 | 0.00 | critical | SSN, date of birth and bank details written to the users collection unen | none (assumptions only) |
| after | t75 | 0.00 | high | SSN, date of birth and bank details written to the users collection in p | none (assumptions only) |
| after | t79 | 0.00 | high | Cross-site request forgery overwrites a victim's SSN, address and bank d | routes/index.js:48 route line (POST /profile) |
| after | t80 | 0.20 | high | Profile fields stored unencrypted in the users collection after POST /pr | routes/index.js:48 route line (POST /profile) |
| after | t81 | 0.05 | critical | SSN, date of birth and bank details submitted over cleartext HTTP on POS | routes/index.js:48 route line (POST /profile) |
| after | t94 | 0.00 | high | Plaintext passwords and SSN/bank fields traverse the MongoDB connection  | none (assumptions only) |

### NG-MISSING-FUNCTION-AUTHZ

> Missing function-level access control. The admin-only /benefits GET and POST routes check only isLoggedIn, not isAdmin, so any user can view or change benefit start dates.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t37 | 0.40 ✓ | high | Cross-site request forgery on state-changing POSTs (/profile, /contribut | routes/index.js:48 gap authn_missing (POST /profile); routes/index.js:52 gap authn_missing (POST /contributions); routes/index.js:67 gap authn_missing (POST /memos) |
| before | t39 | 0.42 ✓ | critical | Missing function-level access control lets any user read and rewrite all | routes/index.js:56 gap authn_missing (POST /benefits); routes/index.js:56 route line (POST /benefits) |
| before | t61 | 0.42 ✓ | critical | POST /benefits is reachable by any logged-in non-admin user, allowing ta | routes/index.js:56 gap authn_missing (POST /benefits); routes/index.js:56 route line (POST /benefits) |
| before | t80 | 0.00 | critical | Unvalidated benefits body lets any logged-in user rewrite other users' b | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t17 | 0.00 | critical | Unauthenticated MongoDB on the benefits-handler to nodegoat flow exposes | none (assumptions only) |
| after | t18 | 0.20 | medium | Unbounded roster read on the benefits flow can be used to exhaust the ap | routes/index.js:55 route line (GET /benefits); routes/index.js:56 route line (POST /benefits) |
| after | t19 | 0.20 | critical | Any logged-in employee can view and rewrite every colleague's benefit st | routes/index.js:55 route line (GET /benefits); routes/index.js:56 route line (POST /benefits) |
| after | t21 | 0.20 | medium | Benefit changes are not attributable to the acting user | routes/index.js:56 route line (POST /benefits) |
| after | t23 | 0.00 | critical | Plain HTTP carries the session cookie and benefits form on the browser-t | none (assumptions only) |
| after | t24 | 0.20 | high | Unvalidated userId in POST /benefits body lets any logged-in user target | routes/index.js:56 route line (POST /benefits) |

### NG-CSRF

> No CSRF protection. The csurf middleware and token are commented out, so state-changing POSTs (profile, contributions, benefits, memos) can be forged.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t37 | 0.40 ✓ | high | Cross-site request forgery on state-changing POSTs (/profile, /contribut | routes/index.js:48 gap authn_missing (POST /profile); routes/index.js:52 gap authn_missing (POST /contributions); routes/index.js:67 gap authn_missing (POST /memos) |
| before | t62 | 0.00 | high | CSRF on POST /contributions lets an attacker's page drive the eval() sin | routes/contributions.js:32 semgrep eval-user-input |
| before | t67 | 0.00 | high | Cross-site request forgery lets a third-party page post memos as the vic | none (assumptions only) |
| before | t71 | 0.00 | high | CSRF on POST /profile lets an attacker overwrite a victim's SSN and bank | none (assumptions only) |
| after | t10 | 0.05 | high | Session fixation and forged state via the in-process auth check with CSR | routes/index.js:44 route line (GET /dashboard) |
| after | t22 | 0.00 | high | Cross-site request forgery on POST /benefits changes another employee's  | none (assumptions only) |
| after | t31 | 0.05 | high | Cross-site request forgery changes another user's contribution percentag | routes/index.js:52 route line (POST /contributions) |
| after | t35 | 0.00 | high | Cross-site request forgery forces a victim's payroll contribution update | none (assumptions only) |
| after | t59 | 0.00 | high | Cross-site request forgery posting memos as a logged-in victim | routes/index.js:67 route line (POST /memos) |
| after | t79 | 0.00 | high | Cross-site request forgery overwrites a victim's SSN, address and bank d | routes/index.js:48 route line (POST /profile) |

### NG-OPEN-REDIRECT

> Unvalidated redirect. GET /learn redirects to req.query.url with no allow-list.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t8 | 0.00 | high | Open redirect on GET /learn reached over the CI-driven HTTP flow takes i | routes/index.js:70 gap input_validation_missing (GET /learn) |
| before | t40 | 0.32 ✓ | high | Open redirect through the url query parameter on GET /learn | routes/index.js:70 gap input_validation_missing (GET /learn); routes/index.js:70 route line (GET /learn) |
| before | t64 | 0.00 | high | Redirect target injected into GET /learn can carry javascript: or data:  | routes/index.js:70 gap input_validation_missing (GET /learn) |
| before | t77 | 0.00 | high | Unvalidated request input reaching the /learn redirect handler on the br | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t12 | 0.01 | high | Unvalidated redirect on GET /learn sends users to an attacker-controlled | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t25 | 0.01 | high | Open redirect on GET /learn steals session-bearing users from the authen | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t27 | 0.01 | high | Unvalidated redirect target on GET /learn reachable over the CI-exercise | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t52 | 0.61 ✓ | high | Open redirect via unvalidated url query parameter on GET /learn | routes/index.js:70 gap input_validation_missing (GET /learn); routes/index.js:70 route line (GET /learn) |
| after | t53 | 0.20 | medium | Redirect target reaching /learn is never logged, leaving phishing redire | routes/index.js:70 route line (GET /learn) |
| after | t54 | 0.47 ✓ | high | Unvalidated redirect on GET /learn?url= sends users to attacker-controll | routes/index.js:70 gap input_validation_missing (GET /learn); routes/index.js:70 route line (GET /learn) |
| after | t55 | 0.00 | high | Session cookie disclosed to the redirect target of GET /learn | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t70 | 0.30 ✓ | high | Known-vulnerable express 4.16.4 and body-parser 1.18.3 expose the server | package.json:13 osv express@4.16.4 GHSA-rv95-896h-c2vc; package.json:13 osv express@4.16.4 GHSA-qw6h-vgh9-j6wx; package.json:9 osv body-parser@1.18.3 GHSA-qwcr-r2fm-qrc7 |
| after | t71 | 0.01 | high | Open redirect on GET /learn forwards authenticated users to attacker-con | routes/index.js:70 gap input_validation_missing (GET /learn) |

### NG-SSRF-RESEARCH

> Server-side request forgery. /research fetches req.query.url + req.query.symbol server-side with needle and echoes the body back to the user.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t42 | 0.05 | critical | Server-side request forgery and response reflection via the url paramete | routes/index.js:76 route line (GET /research) |
| before | t51 | 0.20 | critical | SSRF via attacker-controlled url parameter on GET /research reaching int | routes/index.js:76 route line (GET /research) |
| after | t85 | 0.00 | critical | Server-side request forgery via the url parameter on GET /research | routes/index.js:76 route line (GET /research) |
| after | t97 | 0.20 | critical | Attacker-controlled url parameter on GET /research redirects the server- | routes/index.js:76 route line (GET /research) |

### NG-REDOS-ROUTING

> ReDoS. The bankRouting validation regex /([0-9]+)+\#/ has nested quantifiers and backtracks catastrophically on crafted input.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t46 | 0.05 | critical | Catastrophic-backtracking regex on the bankRouting field allows single-r | routes/index.js:48 route line (POST /profile) |
| before | t58 | 0.40 ✓ | critical | ReDoS via bankRouting on the profile write reached by the same browser s | routes/index.js:67 gap authn_missing (POST /memos) |
| before | t73 | 0.00 | critical | ReDoS via the bankRouting field on POST /profile stalls the single-threa | routes/index.js:70 gap input_validation_missing (GET /learn) |
| after | t65 | 0.75 ✓ | high | Memo rendering denial of service through ReDoS in marked@0.3.5 | package.json:17 osv marked@0.3.5 GHSA-5v2h-r2cx-5xgj; routes/index.js:66 route line (GET /memos); routes/index.js:67 route line (POST /memos) |
| after | t78 | 0.20 | high | ReDoS on POST /profile via the bankRouting field's nested quantifier reg | routes/index.js:48 route line (POST /profile) |
| after | t82 | 0.20 | high | Catastrophic regex backtracking on the bankRouting field stalls the Node | routes/index.js:48 route line (POST /profile) |

### NG-VULNERABLE-DEPS

> Stored XSS in memos through a vulnerable dependency. marked 0.3.5 (package.json and package-lock.json) renders memos via marked(doc.memo), and sanitize:true does not protect it. A finding matches only if it names marked 0.3.5 (or <0.3.6/<0.3.7) and GHSA-vfvf-mqq8-rwqc (CVE-2016-10531, sanitize bypass via HTML entities, fixed 0.3.6) or GHSA-7px7-7xjx-hxm8 (CVE-2017-1000427, XSS via data URIs, fixed 0.3.7). A generic "outdated dependencies" or marked ReDoS finding does not match.

| run | id | conf | sev | title | cited evidence |
|---|---|---|---|---|---|
| before | t4 | 0.42 ✓ | high | Stored cross-site scripting through memo text rendered on /memos | routes/index.js:67 gap authn_missing (POST /memos); routes/index.js:67 route line (POST /memos) — _does NOT cite a required advisory_ |
| after | t60 | 0.20 | critical | Stored XSS injected through the POST /memos memo field and rendered as r | routes/index.js:67 route line (POST /memos) — _does NOT cite a required advisory_ |
| after | t63 | 0.75 ✓ | critical | Stored XSS in shared memos via unsanitised Markdown rendered by marked@0 | package.json:17 osv marked@0.3.5 GHSA-7px7-7xjx-hxm8; routes/index.js:66 route line (GET /memos); routes/index.js:67 route line (POST /memos) — _cites required GHSA-7px7-7xjx-hxm8_ |
| after | t65 | 0.75 ✓ | high | Memo rendering denial of service through ReDoS in marked@0.3.5 | package.json:17 osv marked@0.3.5 GHSA-5v2h-r2cx-5xgj; routes/index.js:66 route line (GET /memos); routes/index.js:67 route line (POST /memos) — _does NOT cite a required advisory_ |

## 2. Threats with no suggested expected match

Grouped by first CWE so repeats can be labelled together. Most are outside the answer key (CI, seeding, containers, repudiation, DoS, MongoDB link) and would take a blank `matchesExpected`.

### before (39 of 86)

- **CWE-306** (4): t7 Unauthenticated actor on the CI network reaches the app ✓ · t10 Unauthenticated reset/seed path on the DAO-to-Mongo con · t21 Unauthenticated MongoDB on the compose network can be d · t35 No authentication on MongoDB means database writes cann
- **CWE-778** (4): t13 DAO writes to users, allocations and contributions leav · t19 Seed job writes no audit record of collection drops and · t30 End user can deny posting a memo or changing bank detai · t44 No per-user audit trail for benefit and profile changes ✓
- **CWE-20** (4): t53 The url and symbol query parameters on the /research fl · t60 POST /benefits accepts unvalidated userId and benefitSt · t69 Unvalidated memo body is stored and rendered to every u · t85 Unvalidated login credentials passed from the session h
- **CWE-1104** (3): t15 Vulnerable mongodb 2.2.36 driver used by all DAOs is su ✓ · t24 Container image built on end-of-life node:12-alpine bas · t36 Denial of service against the nodegoat datastore via vu ✓
- **CWE-1188** (3): t18 Seed script drops production collections on every conta · t23 Web container publishes port 4000 to all host interface · t34 Unauthenticated MongoDB in docker-compose allows tamper
- **CWE-400** (3): t27 Unbounded pull_request CI matrix allows runner-minute e · t54 GET /research can be used to make the app host issue un · t83 Unbounded memo insertion and unbounded memo read over t
- **CWE-494** (3): t28 Lint workflow runs an unpinned remote linter fetched at · t31 Unpinned third-party actions and lint tool fetched at r · t52 Remote content from the stock fetcher is written unesca
- **CWE-307** (3): t38 No rate limiting on POST /login and POST /signup allows · t66 Unthrottled credential stuffing against POST /login · t76 Unthrottled account creation and credential submission 
- **CWE-209** (1): t5 Error handler renders exception messages and stack cont
- **CWE-1392** (1): t17 Seed job installs well-known default accounts including
- **CWE-665** (1): t22 Web container start command retries a database reset sc
- **CWE-732** (1): t25 Production hardening of the app directory is left comme
- **CWE-829** (1): t26 E2E workflow triggers on pull_request with unpinned thi
- **CWE-506** (1): t32 CI workflow triggers on pull_request and runs repositor
- **CWE-200** (1): t33 Failed E2E runs upload Cypress videos and screenshots o
- **CWE-1395** (1): t43 Vulnerable express 4.16.4 and body-parser 1.18.3 expose ✓
- **CWE-311** (1): t49 Login credentials and full user documents cross to the 
- **CWE-319** (1): t50 Outbound stock quote fetch is not pinned to HTTPS, allo
- **CWE-770** (1): t70 Unbounded memo submissions exhaust MongoDB storage and 
- **CWE-352** (1): t75 State-changing POST routes for profile, contributions,  ✓

### after (50 of 109)

- **CWE-306** (6): t1 MongoDB connection from the Allocations Handler is unau · t38 MongoDB connection string in docker-compose.yml uses no · t41 Seeder and DAO traffic to MongoDB travels unauthenticat · t45 Unauthenticated MongoDB endpoint lets an attacker on th · t56 MongoDB wire traffic on the memo flow travels unauthent · t74 Profile writes to MongoDB cross the container boundary 
- **CWE-770** (5): t3 Unbounded allocations query from the handler can be use · t58 Unbounded memo listing over the memo flow exhausts memo · t62 Unbounded memo body allows storage exhaustion of the me · t76 Unbounded profile field sizes let a user inflate the us · t108 Unthrottled POST /signup flow permits mass account crea
- **CWE-778** (5): t4 No per-request audit trail for cross-user allocation re · t33 Contribution updates are not attributable because no au · t44 Seeder leaves no attributable record of who reset and r · t66 No per-user attribution for writes to the memos collect · t95 Login and signup outcomes are not audited, leaving cred
- **CWE-400** (5): t11 Unbounded session-checked request handling lets a singl · t86 Unbounded outbound fetch on GET /research exhausts serv · t89 Server-side fetch on /research used to exhaust the Node · t96 Loss of the single MongoDB instance halts all authentic · t99 Unbounded server-side fetch on /research allows resourc
- **CWE-1188** (4): t29 Unauthenticated MongoDB endpoint lets any process on th · t40 web container startup loop re-runs db-reset.js, allowin · t43 Startup seeder drops every collection, destroying live  · t103 Tutorial pages leak the built-in admin credentials to u
- **CWE-1104** (3): t16 Swig 1.4.2 arbitrary local file read through template r · t47 Container image built on end-of-life node:12-alpine bas · t69 Vulnerable mongodb 2.2.36 driver allows denial of servi
- **CWE-79** (3): t84 Fetched remote HTML echoed into the response enables st · t88 Reflected untrusted remote content injected into the /r · t98 Remote page content fetched by /research is written une
- **CWE-20** (2): t20 Unvalidated benefitStartDate and userId written to the  · t57 Memo insert accepts arbitrary non-string bodies straigh
- **CWE-319** (2): t30 Unencrypted MongoDB wire traffic between the Contributi · t83 Outbound research fetch accepts an attacker-chosen, pos
- **CWE-200** (2): t102 Tutorial pages advertise exploitable routes and paramet · t105 Unauthenticated /tutorial pages disclose the applicatio
- **CWE-639** (1): t28 CI drives /allocations/:userId with no ownership check,
- **CWE-1035** (1): t39 Outdated mongodb 2.x driver pinned in package.json
- **CWE-1392** (1): t42 Seeder writes fixed default admin and user accounts wit
- **CWE-668** (1): t46 web container publishes port 4000 on all host interface
- **CWE-732** (1): t48 Production hardening of the app directory is left comme
- **CWE-349** (1): t49 E2E workflow triggers on pull_request with unpinned thi
- **CWE-829** (1): t50 CI workflow runs on pull_request from forks and execute
- **CWE-532** (1): t51 Cypress failure artifacts uploaded publicly may leak se
- **CWE-282** (1): t64 Memos are stored and displayed with no author identity 
- **CWE-209** (1): t73 Unhandled error stacks rendered to the browser by the g
- **CWE-613** (1): t90 Admin authorisation depends only on a session userId lo
- **CWE-284** (1): t91 MongoDB reachable without authentication, permitting di
- **CWE-307** (1): t107 Unthrottled POST /login flow allows credential stuffing

