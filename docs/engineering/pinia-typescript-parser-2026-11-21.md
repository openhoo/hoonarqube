# Pinia's TypeScript properties named `abstract`

Hoonarqube now completes the Pinia scan that failed in the
[120-project comparison](public-projects-2026-11-21.md). That comparison
retains its original build and counts.

In Pinia, `abstract?: boolean` declares a property named `abstract`. The
vendored Tree-sitter grammar treated that token as a modifier and produced a
syntax error. The TypeScript and TSX grammars now accept it as a property name
in a type signature. The existing modifier and parser error handling stay in
place.

## What the replay found

At Pinia commit `4023d1233724ae478da09c81a5b65ad815cc1358`, the same scope
under `packages/pinia/src` went from an incomplete scan (exit 2, 18 complete
files) to a complete scan (exit 0, 19 complete files). The newly measured file,
`devtools/formatting.ts`, contributes 216 physical lines, 194 code lines and
6 comment lines. Its 67 native findings and the other 18 file reports were
unchanged.

The retained SonarQube Community Build capture indexed 18 files. Hoonarqube
also scanned `global.d.ts`, so the comparison covers the 18 shared files.
All 54 line, code-line and comment-line values agree on those files. For
active rules with matching declared parameters, 48 primary findings matched,
14 were native only and 7 were reference only.

TypeScript 5.9.3 produced no syntax diagnostics across the 19 pinned sources
and identified both optional `abstract` properties. The compiler and the
scanner still reject the malformed and misplaced-modifier controls. Across
the other 12 TypeScript selections (11 repositories), the native reports
were byte-for-byte identical to the previous run.

The [combined release replay](scanner-corpus-replay-2026-11-21.md) covers all 122 public scopes and the 25 maintained CI contracts.
