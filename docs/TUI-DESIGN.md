# Terminal interface & Dynamic Cybersecurity HUD

The interface is a state-of-the-art phosphor-green cybersecurity instrument panel inspired
by high-tech military/sci-fi HUD monitors and system observability tools:
- **Dynamic scanning simulation**: real-time rotating target radar reticle, cryptographic token decryption streams, oscilloscope audio/signal spectrum waveforms, and AST node graph meshes.
- **Reporting Cockpit**: static target lock reticle, LCD numerals, DEFCON threat status, vulnerability density seismograph, engine defense matrix, and contextual finding cards.

## Visual Patterns & Cybersecurity HUD (Reference: image copy.png & image.png)

| Cyber HUD Component | Terminal Implementation | Interactive Live State |
|---|---|---|
| **Circular Radar Reticle** | 8-azimuth concentric circle HUD (`000°` to `315°`), crosshair `⌖`, threat blips (`●`, `▲`) | Rotating sweep ray (`↑`, `↗`, `→`, `↘`, `↓`, `↙`, `←`, `↖`) |
| **Token Decryption Stream** | Scrambled cipher blocks `[ S ][ E ][ N ][ T ][ I ][ N ][ E ][ L ]` with progress slider | Scrambling hex characters resolving into locked tokens |
| **Oscilloscope Waveforms** | Dual harmonic frequency bars (` ▂▃▅▆▇█`) + spectrum dB and entropy telemetry | Dynamic phase-shifted wave reactive to scanning velocity |
| **AST Constellation Mesh** | Vertical call graph nodes `(●)──(○)──(●)` with linking vectors | Pulsing active nodes as AST trees are traversed |
| **Engine Cockpit** | Status badges `[ READY ]`, `[ OPTIMAL ]`, `[ DEGRADED ]`, `[ BYPASS ]` | Live spinners `⠋⠙⠹...` and engine state pills |
| **Transition Animation** | Wipes HUD cleanly into the final report | 300ms matrix convergence frame |

## Palette

| Role | Colour | Used for |
|---|---|---|
| Neon | `38;5;48` | ultra-vibrant electric matrix green, active locks |
| Primary | `38;5;42` | wordmark, panel titles, healthy state |
| Bright | `38;5;120` | values, file paths, emphasis |
| Cyan / Electric | `38;5;51` / `38;5;44` | telemetry streams, line numbers, medium severity |
| Muted | `38;5;35` | body text, labels, borders |
| Dark | `38;5;22` | rules, secondary metadata, empty bar cells |
| Amber | `38;5;214` | high severity, warnings, degraded engines |
| Red | `38;5;196` / `38;5;203` | critical severity, failures, DEFCON-1 |
| Magenta | `38;5;171` | GitHub Actions rules |

Severity carries one colour everywhere: the dial, the distribution bar, the legend and the
finding card all use the same value. A colour that means "critical" in one place and
something else in another is worse than no colour.

## Glyph discipline

**Nothing non-ASCII may be written directly into a format string.** Every box corner,
bullet, dot and bar cell comes from `internal/ui`.

This rule exists because violating it produced the exact bug the redesign was meant to
fix: boxes correctly degraded to `+---+` while a hardcoded `·` printed as `┬╖` and a `●` as
`ΓùÅ`, so one screen looked like two programs rendering it.

Helpers: `BoxFor()`, `Separator()`, `MarkOn()`, `MarkOff()`, `MarkHalf()`, `DashGlyph()`,
`BlockGlyph()`, `Sym.OK`, `Sym.Fail`, `Sym.Warn`, `Sym.Arrow`, `Sym.Rule`.

`SENTINEL_GLYPHS=ascii` forces the fallback set.

## Colour detection

| Condition | Result |
|---|---|
| stdout redirected or piped | no colour, layout unchanged |
| `NO_COLOR` set | no colour — the agreed opt-out, never overridden |
| `SENTINEL_COLOR=always` | colour even when piped |
| `SENTINEL_COLOR=never` | never colour |
| otherwise, interactive terminal | colour |

Detection lives in exactly one place: `internal/ui`'s `init`. An earlier version also
called `DisableColors` from `internal/report`'s `init`; that ran afterwards and silently
defeated a force request, so colour could not be regained once output was piped.

## Width

72 columns of content, plus two border columns and a two-space gutter: 76 total. That fits
the 80-column default of `cmd.exe`, most CI log viewers, and an 80-column pane with a
divider. A layout that only works at 120 columns breaks precisely where people read it.

## Layout

```
  [ block wordmark ]     VERSION  1.0.2
                         AUTHOR   Afjal (@DraculaHub786)
                         MODE     LOCAL-FIRST
                         EGRESS   NONE
                         LICENSE  MIT
  ── DEVSECOPS UNIFIED SCANNER ──────────────────────────────
  <repo url>

  ╭─ SCAN OVERVIEW ───────────────────────────────────────────╮
  │ TARGET path   MODE FULL   8714ms                          │
  │  ### # #                                                  │
  │    # # #                                                  │
  │  ### ###   HIGH SEVERITY   <- caption on the middle row    │
  │  #     #                                                  │
  │  ###   #                                                  │
  │ ███████████████████████████████████████░░░░░░░░░░░░░       │
  │ 0 CRIT  14 HIGH  8 MED  2 LOW  0 INFO                     │
  ╰───────────────────────────────────────────────────────────╯
  ╭─ ENGINE COVERAGE ─────────────────────────────────────────╮
  ╭─ WARNINGS ────────────────────────────────────────────────╮
  ╭─ FINDINGS · HIGH · 14 ────────────────────────────────────╮
  │  [ HIGH ]  app.js:17                                      │
  │    Hardcoded JWT secret key string literal detected.      │
  │    risk 58.8   secret   external   CWE-798                │
  │    org-hardcoded-jwt-secret   SENT-491c28fa63d2           │
  ╰───────────────────────────────────────────────────────────╯
   NEXT   sentinel explain <id>  ·  sentinel fix <id> --apply
   OK gating passed · nothing at or above 'high'
```

## Defects this design fixed

Each was observed in real output during the redesign, not predicted:

| Defect | Cause | Fix |
|---|---|---|
| `[HIGH]` glued to the filename | concatenation with no separator | explicit two-space gap |
| Wordmark in block glyphs beside `+---+` panels | hardcoded `█` in `letterFont` | `BlockGlyph()` substitution |
| `11` rendered as an unreadable block mass | no gap between 3-column digits | one blank column between glyphs |
| Caption repeated on all five dial rows | caption appended per row | caption on the middle row only |
| Metadata row overran the right border | six fields on one line | split into two rows |
| Raw CWE description overflowed | `[CWE-250: Execution with...]` printed verbatim | `cweLabel()` keeps `CWE-250` |
| `┬╖`, `ΓùÅ` mojibake | glyphs in format strings | routed through helpers |
| Findings flush against the border | no indent | three-space indent |
| Colour impossible to force | second `DisableColors` in a later init | detection only in `internal/ui` |

## Verification

```
go build -o bin/sentinel.exe ./cmd/sentinel
bin/sentinel.exe scan testdata/breadth     # populated report
bin/sentinel.exe scan testdata/safe-app    # clean state
bin/sentinel.exe version
bin/sentinel.exe doctor
```

Colour behaviour:

```
SENTINEL_COLOR=always bin/sentinel.exe version | grep -c $'\033'   # > 0
bin/sentinel.exe version | grep -c $'\033'                          # 0
```

Widest line must stay at or under 78 visible columns.
