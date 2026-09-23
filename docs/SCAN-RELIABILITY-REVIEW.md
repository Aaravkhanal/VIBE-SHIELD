# Scan reliability and interface review

The review traced the CLI, crawler, module orchestration, web/CI entry points,
report generators, scoring and dashboard. Syntax checks cover all JavaScript
source files. This is a focused repair and regression review, not a claim that
all vulnerability detectors or every third-party application were exhaustively tested.

## Confirmed defects repaired

- Web and webhook scans read the alphabetically newest report, regardless of scan
  ID or target. Failures could display earlier results and fabricated passing scores.
- The crawler never resolved when its page limit left more URLs queued.
- Failed discovery continued into downstream scanners and could appear clean.
- XSS execution markers contained spaces, causing invalid JavaScript.
- Header checks refetched with HEAD and ignored route-specific browser responses.
- Dependency auditing attributed the scanner's own package tree to every website.
- Live updates depended on parsing terminal spinner text; progress events were lost.
- HTML fallback used CommonJS `require` in an ES module with the wrong API.
- Executive report controllers addressed obsolete element IDs and supplied fake
  scores, compliance claims and durations when no report was available.
- Trend charts invented earlier scans; surface maps invented common routes and
  threat graphs added unverified exploit paths.
- Findings and reports mixed raw and deduplicated totals; table columns became
  unreadable at narrow widths. Report reproduction steps contained literal `\n`.
- The published npm file list omitted frontend assets.
- CI shell construction used `eval`, and scanner errors could produce a passing gate.

Additional fixes include consistent shared scoring, per-module error reporting,
explicit unassessed categories, matching-target diff history, cryptographic IDs
using Node's built-in crypto, loopback binding and cross-origin request rejection.
The previous Nano ID dependency was removed; see the upstream
[advisory](https://github.com/advisories/ghsa-28wg-ghj8-5hjv).

## Validation and remaining limits

`npm test` covers state transitions, missing/wrong reports, scoring, module failure,
crawl limits, captured headers, report formats, dependency scope and ID generation.
`npm run test:browser` runs a real Chromium against controlled local fixtures and
checks the full scan-to-report workflow, simultaneous scans, failure gates and UI.
The GitHub Action's shell blocks are syntax-checked; the hosted Action itself was
not executed during this local review.

The npm advisory endpoint failed twice with TLS connection errors, so no clean
full dependency-audit result is claimed. Authenticated, AI-model and business-logic
scans still depend on the target's reachable surfaces, credentials and supported
protocols. Some individual probes intentionally continue after request failures;
module-level errors and coverage are now visible, but a completed scan is not an
exhaustive assessment. Existing historical reports cannot retroactively establish
coverage. Run new scans for current evidence.
