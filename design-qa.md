# Design QA

- Source visual truth: `/tmp/codex-clipboard-274cefba-4d5e-45cc-88fb-24d61367208e.png`
- Implementation screenshot: `/tmp/advanced-ip-analyser-v040-main.png`
- Service-fingerprint screenshot: `/tmp/advanced-ip-analyser-v050-fingerprints.png`
- Service-fingerprint comparison: `/tmp/advanced-ip-analyser-v050-comparison.png`
- Automatic-update button screenshot: `/tmp/advanced-ip-analyser-v051-update-button.png`
- Two-phase discovery indicator screenshot: `/tmp/codex-clipboard-364b1ac0-8a84-4495-aa56-9e9d2cb01902.png`
- Help screenshot: `/tmp/advanced-ip-analyser-v040-help-final.png`
- Combined comparison: `/tmp/advanced-ip-analyser-v040-design-comparison.png`
- Source pixels: 653 x 425
- Implementation pixels: 1332 x 779
- Comparison normalization: source 653 x 425; implementation proportionally resized to 727 x 425; density 1
- Implementation viewport: native 1200 x 620 Tk content window with KDE decoration
- State: populated results table, first host expanded, first host selected

## Full-view comparison evidence

The combined comparison confirms the requested visual relationships. Both views
use a compact blue desktop frame, a white results surface, blue selection, native
disclosure arrows, and hierarchical child rows. The implementation retains the
existing application's larger administration toolbar and wider data model rather
than copying the reference application's branding, icons, or exact chrome.

## Focused region comparison evidence

The table region is readable in the full comparison: alternating host rows are
white and pale blue; the selected parent is saturated blue; child rows use a
quieter pale-blue detail surface; and the expanded host exposes separate rows for
ports 80, 443, and 9100 with state, service, and connection detail. A separate
crop was unnecessary because all requested table details remain legible in the
native implementation capture.

The illustrated Help window was captured separately. Its five tabs, synchronized
version, fixed header Close control, explanatory copy, and embedded screenshots
are visible without clipping at the tested viewport.

## Findings

No actionable P0, P1, or P2 mismatch remains for the requested changes.

The v0.5.0 comparison adds the requested third tree level without changing the
established layout or colour system. The selected HTTP row clearly identifies
Apache in-line, while its expanded children separate Status, Server, Powered by,
Content type, and Page title into readable label/value rows. Native arrows make
the host-to-port-to-metadata hierarchy unambiguous, and the pale metadata surface
remains distinct from both alternating host stripes and clickable blue rows.

## Required fidelity surfaces

- Fonts and typography: native Tk/KDE UI font is consistent across controls and table; bold table headers establish hierarchy.
- Spacing and layout rhythm: compact two-row controls remain aligned; table receives the dominant area; no controls overflow at the tested viewport.
- Colors and visual tokens: blue frame/header/selection, pale-blue alternate rows, green primary action, and pale-red dangerous actions are visibly distinct.
- Image quality and asset fidelity: no external image assets were needed or copied; disclosure controls are native Treeview affordances.
- Copy and content: parent rows show port counts; child rows show port number, Open state, service name, and URL or TCP detail.

## Comparison history

- Initial pass: blocked because an X display had not yet been discovered.
- Fix: located the active KDE Xwayland session, launched a populated native Tk state, captured the active window, and created a normalized combined comparison.
- Iteration two: the first Help capture showed that a bottom Close button could be displaced by the overview image.
- Fix: moved Close into the fixed Help header and recaptured the window.
- Post-fix evidence: `/tmp/advanced-ip-analyser-v040-design-comparison.png` and `/tmp/advanced-ip-analyser-v040-help-final.png`; no P0/P1/P2 findings remain.

## Implementation checklist

- Completed: blue desktop colour system.
- Completed: alternating white and light-blue host rows.
- Completed: expandable host parents with per-port child details.
- Completed: selected, expanded, and collapsed states visually verified.
- Completed: clickable service styling, footer version, and illustrated Help centre visually verified.
- Completed: nested server fingerprints, including Apache/nginx names and HTTP/TLS details, visually verified at the native viewport.
- Completed: the conditional update control is prominent without displacing the Help, version, attribution, or progress controls; both flashing colour states were exercised.
- Completed: the blue discovery indicator, numeric phase progress, completed host rows, footer status, version, attribution, and progress bar fit the native 1200 x 620 layout without clipping.

The discovery screenshot used a deliberately paused three-host fixture solely to
verify the in-progress state. It was closed immediately after capture and was not
a live scan. No further visual fixtures should be opened on the user's desktop
without explicit notice.

## Follow-up polish

- Optional P3: add application-owned icons later if an original icon family is commissioned.

final result: passed

## Dashboard operations layout — November 2026

- Reference: `6032.png`, a dense dark operations dashboard with two stacked
  blue line/area charts, compact status lists, and circular summary indicators.
- Native render: `docs/images/dashboard-operations.png`, Advanced IP Analyser at
  1440 x 850 with representative scan, activity, traffic, favourite, and system data.

### Fidelity and usability review

- The native dashboard follows the reference hierarchy: summary strip, stacked
  time-series charts on the left, compact live information in the centre, and
  circular indicators on the right.
- Navy surfaces, thin blue-grey borders, restrained cyan/green/orange status
  colours, white chart traces, and blue area fills match the reference direction.
- Existing navigation, live sampling, scan metrics, recent activity, favourites,
  and system information remain functional and use real application data.
- Both charts resize with the window, use bounded history, show an explicit
  collecting state, and avoid clipped labels at the tested viewport.
- Ring labels describe operational coverage and inventory completeness; they do
  not imply malware protection or a security verdict.

### Issues resolved

- P1: Short traffic histories occupied only part of the plot. Fixed by scaling
  available samples across the complete chart width.
- P2: Fractional tick labels displayed excessive precision. Fixed with concise
  one-decimal formatting and removal of unnecessary trailing zeroes.

### Remaining polish

- P3: At the minimum supported window width, the main feature-tab row remains
  visually dense. It is still usable and unchanged by this dashboard update.

final result: passed
