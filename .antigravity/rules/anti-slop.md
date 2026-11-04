# Anti-Slop Rules & Standards

> **Origin**: Derived from [miqdadbadjuber/anti-slop](https://github.com/miqdadbadjuber/anti-slop)  
> **Scope**: All AI coding agents and human developers contributing to VulnSight AI.

---

## 1. Core Principle
VulnSight AI is an **enterprise security engineering platform**. Every line of code, UI component, copy string, and commit must serve an authentic operational purpose. Generic AI boilerplate, cliché templates, marketing buzzwords, and redundant comments are strictly prohibited.

---

## 2. The 3-Tier Rulebook

### Tier 1: Hard Gates (Immediate Fail, Zero Exceptions)
* **HG-01 (Data Authenticity)**: Never fabricate or simulate placeholder numbers or statuses. If an entity (e.g. repo, scan) has no data, show an explicit empty state with an actionable next step. Never default posture to "100" without actual scan results.
* **HG-02 (Copywriting Honesty & Punctuation)**: 
  * **Banned Words**: *supercharge, seamless, seamlessly, revolutionize, unlock the power of, empower, elevate, delve, game-changing, synergy, cutting-edge, next-gen*.
  * **Banned Punctuation**: Em dash (`—`). Use commas, colons, periods, or parentheses instead.
  * **Banned Phrasing**: Conversational AI fluff like *"As an AI security assistant..."*, *"Certainly, here is..."*, or *"In today's fast-paced security landscape"*.
* **HG-03 (WCAG AA Contrast)**: Minimum 4.5:1 text contrast for body text; 3:1 for large text and graphical components.
* **HG-04 (Interaction Completeness)**: No dead buttons or placeholder links (`href="#"`). Every clickable element must execute a functional handler, router change, drawer, or modal.
* **HG-05 (Accessible Focus States)**: `:focus-visible` with a clear 2px outline and 1px offset must be preserved on all interactive controls.

### Tier 2: Purpose Gates (Allowed Only with Functional Justification)
* **PG-01 (Motion Restraint)**: No gratuitous, bouncy, or spring animations. Animations are restricted to functional feedback (e.g., scan progress spinners, drawer transitions) and capped at 150ms linear/ease.
* **PG-02 (Semantic Color Exclusivity)**: Colors (Red, Orange, Amber, Blue, Green) must signify vulnerability severity or operational state. Never use decorative color fills or neon glow shadows.
* **PG-03 (High-Density Layouts)**: Favor dense data tables, tabular statistics, and collapsible side inspectors over multi-step modal wizards.

### Tier 3: Quality Locks (Systemic Consistency)
* **QL-01 (Geometry Scale)**:
  * Tags & small badges: `4px` (`--radius-xs`)
  * Interactive controls (buttons, inputs, select): `6px` (`--radius-sm`)
  * Panels, cards, and tables: `8px` (`--radius-md`)
  * Absolutely no bubbly `rounded-full` / `9999px` pill shapes for buttons or cards.
* **QL-02 (Tabular Numerals)**: `font-variant-numeric: tabular-nums` is mandatory on all counts, metrics, CVE scores, and timestamps.
* **QL-03 (Monospace Formatting)**: All CVE IDs, package names, commit hashes, file paths, and code snippets must use `var(--font-mono)`.
* **QL-04 (Theme Depth)**: Use deep solid dark neutrals (`#090d16` base, `#161b22` cards, `#21262d` elevated) rather than washed-out generic gray.

---

## 3. Code & Comment Stripping (`antislop-code`)
* **Strip Narrator Comments**: Delete comments that merely describe standard language syntax (e.g., `// loop over items`, `// set state to false`, `// check if error exists`).
* **Preserve Invariant Comments**: Retain comments that explain non-obvious security invariants, external tool quirks, or architectural isolation boundaries (e.g., Gitleaks secret redaction, tenant isolation).
* **Eliminate Single-Use Abstractions**: Do not create wrapper functions, utility files, or defensive abstractions for simple 1-line operations.

---

## 4. Delivery Gate Verification Checklist
Before approving or shipping any pull request or commit, verify:
- [ ] **Hard Gates**: 0 fabricated metrics, 0 banned buzzwords, 0 em dashes, 0 dead controls.
- [ ] **Purpose Gates**: 0 decorative animations, 0 arbitrary color fills, density preserved.
- [ ] **Quality Locks**: Strict 4/6/8px radii, tabular-nums active, monospace on all identifiers.
- [ ] **Code Hygiene**: 0 narrator comments, 0 redundant wrappers.
- [ ] **Tests & Build**: `npm test` passes 100% and `npm run build:web` succeeds.
