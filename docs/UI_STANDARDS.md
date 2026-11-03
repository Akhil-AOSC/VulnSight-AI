# VulnSight AI — Frontend Architecture & UI Standards (No-Slop Standard)

> **Standard Origin**: [LeoStehlik/no-slop-ui](https://github.com/LeoStehlik/no-slop-ui.git)  
> **Target Audience**: Core developers and AI coding agents working on the VulnSight AI Enterprise Platform.

---

## 1. Core Philosophy: The Anti-Slop Directive

VulnSight AI is an **enterprise security engineering platform**, not a consumer landing page or promotional demo. The interface must prioritize:
1. **High Information Density**: Enable security analysts to scan dozens of findings without endless scrolling.
2. **Solid Surfaces & Crisp 1px Borders**: Depth is communicated via subtle neutral color stepping, not fuzzy blurs or glowing box shadows.
3. **Semantic Restraint**: Reserve color for actionable severity (Critical, High, Medium, Low, Clean). Do not paint cards or headers in purple/indigo gradients.
4. **Predictable Typography & Alignment**: Use monospace tabular numbers for counts, percentages, and metrics to prevent layout shifts. Monospace for hashes, CVE IDs, and file paths.

---

## 2. Forbidden Anti-Patterns ("AI UI Slop")

The following patterns are **strictly prohibited** in all pull requests:

| Slop Anti-Pattern | Why it is Banned | What to Use Instead |
| :--- | :--- | :--- |
| **Decorative Gradients** | `linear-gradient(...)` across cards, headers, and text distracts from vulnerability triage. | Solid neutral surfaces (`--surface`, `--surface-2`). |
| **Frosted Glass / Blurs** | `backdrop-filter: blur(...)` causes GPU lag and impairs readability. | Solid opaque backgrounds with 1px border. |
| **Glowing Box Shadows** | `box-shadow: 0 0 20px var(--brand)` looks like a gaming dashboard. | Subtle grounding shadows (`0 1px 2px rgba(0,0,0,0.5)`). |
| **Pill Badges (`radius: 9999px`)** | Bulky pills consume too much horizontal real estate in tables. | Compact 4px tags (`--radius-xs`) with monospace tabular text. |
| **Dashed Borders** | `border: 1px dashed var(--brand)` looks like an unfinished sketch. | Clean solid 1px borders with an optional 2px or 3px solid accent bar. |
| **Card Inception** | Nesting bordered cards inside bordered cards creates visual clutter. | Flatten with subtle background contrast (`--surface-2`) or 1px dividers. |
| **Bouncy / Spring Animations** | Slows down engineers navigating between findings and repos. | Instant or 0.1s linear/ease transitions. |

---

## 3. Geometry & Spacing Rules

- **Controls** (`<button>`, `<input>`, `<select>`, `<textarea>`):
  - Border radius: **`6px`** (`--radius-sm`).
  - Height: `32px` to `36px`.
  - Padding: `0.4rem 0.75rem`.
- **Badges & Tags**:
  - Border radius: **`4px`** (`--radius-xs`).
  - Font family: `var(--font-mono)`.
  - Padding: `1px 5px`.
- **Containers & Tables** (`.card`, `.table-wrap`, modal dialogs):
  - Border radius: **`8px`** (`--radius-md`).
  - Table rows: `34px` to `38px` compact height.
  - Border: `1px solid var(--border)`.

---

## 4. Typography Rules

- **General Body**: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`.
- **Numbers & Metrics**: `font-variant-numeric: tabular-nums` (mandatory on all tables, gauges, and stat cards).
- **Code, CVEs, Hashes & Paths**: `var(--font-mono)` (`ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace`).

---

## 5. Pre-Flight PR Checklist

Before submitting or approving any UI change:
- [ ] Are all card surfaces solid (zero gradients, zero backdrop blurs)?
- [ ] Are buttons and inputs bounded by 6px radius (`--radius-sm`)?
- [ ] Are badges and tags bounded by 4px radius (`--radius-xs`)?
- [ ] Are table numbers and counters rendered in `tabular-nums`?
- [ ] Are CVEs, commit hashes, and file paths wrapped in `<code>` or `.mono`?
- [ ] Did `npm run build:web` bundle successfully with zero errors?
- [ ] Did `npm test` pass with 100% of test suites green?
