# Workspace Instructions & Rules

## Mandatory Frontend Design Protocol: `unslop`

Whenever the user asks to make, build, design, create, update, or polish any frontend, UI, dashboard, component, or web interface:
1. **Activate the `unslop` skill**: Use the `unslop` skill (`.agents/skills/unslop/SKILL.md`) for all frontend design decisions.
2. **Direction First**: Before generating code, define the Product, Character, World, Moments (1-2 rich focal points), and Signature.
3. **Eliminate Slop**:
   - Zero purple/violet gradients across cards, surfaces, or text.
   - Zero colored glows, neon shadows, or radial gradient wash blobs.
   - Zero emoji in headings, cards, badges, or buttons. Use single-family line icons (e.g. Lucide) with consistent 16/18px stroke.
   - Zero AI marketing fluff (*"Supercharge"*, *"Revolutionize"*, *"Seamlessly elevate"*, *"New ✨"*).
   - Zero bubbly `rounded-full` pills for standard cards or buttons. Follow strict radii: `4px` tags/badges, `6px` inputs/buttons, `8px` cards.
4. **Follow the 9 Passes**:
   - 1. Spacing (strict 4px grid)
   - 2. Color (tinted neutral ramp, quiet chrome, semantic colors only for data status)
   - 3. Icons (uniform stroke and sizing)
   - 4. Copy (direct, specific, clear actions)
   - 5. Type (strict hierarchy, tabular numbers for metrics)
   - 6. Layout (anchored, dense, clear structure)
   - 7. Details (crisp hairlines, 4.5:1 contrast, visible focus states)
   - 8. Visuals (authentic product representations with one bright moment)
   - 9. Motion (functional, feedback only $\le 150\text{ms}$)

