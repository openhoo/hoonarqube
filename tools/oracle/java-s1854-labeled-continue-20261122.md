# Java S1854: labeled loops and suppressed local declarations

After [the switch entry fix](java-s1854-switch-20261122.md), eight native-only
locations remained in the additional public scopes. Seven stores were live
on the next iteration of an explicitly labeled loop. The eighth was a dead
initializer that SonarJava excludes through `@SuppressWarnings("unused")`.

## What changed

- An unlabeled `continue` now follows the nearest loop's continuation
  target, even when that loop has a label. Named `continue` and `break`
  still match their existing targets.
- A local declaration may suppress S1854 with the built-in annotation and
  positional literal warning values. This affects reporting on the
  declaration; its reads, writes, and calls remain in the analysis.
  The rule keeps reporting declarations with unrelated warning values or
  explicitly named `value = …` arguments, as the tested SonarJava version
  did. Named arguments, enclosing class or method annotations, and
  evaluation of constant expressions are outside this implementation.

In Commons Text's `StringSubstitutor.java:1449`, the updated `pos` is read in
the next condition of `outer: while`. In Gson's `JsonReader.java`, the writes
on lines 847, 848, 851, 858, 866, and 873 are read after an unlabeled
`continue` in `charactersOfNumber: for`. Changing only the spelling of the
six jumps in copies of those two files, so that they named the same loop
targets explicitly, removed exactly the seven reports in the earlier CLI.

The Gson declaration at `JsonTreeReader.java:336` intentionally discards the
result of `nextName(true)`. The call still advances the iterator and updates
reader state. SonarJava 8.41 build 47177 explicitly maps the `unused` warning
to `java:S1854` in [its suppression filter at the installed revision](https://github.com/SonarSource/sonar-java/blob/68605929e2ce0013fdbe7852937ab4e5681c411e/java-checks/src/main/java/org/sonar/java/filters/SuppressWarningFilter.java#L74).

## Exact before and after locations

The [scope and pin table](java-s1854-switch-20261122.md) identifies the same
public source commits, file sets, and Sonar reference scans used here.
All counts compare file path and UTF-16 start and end positions.

| Scopes | Files | Native only before → after | Exact matches preserved | Reference only before → after |
| --- | ---: | ---: | ---: | ---: |
| Seven archived Java scopes | 407 | 0 → 0 | 7 | 3 → 3 |
| Six additional Java scopes | 1,165 | 8 → 0 | 9 | 0 → 0 |

The eight removals were one in Commons Text and seven in Gson. Findings for
other rules stayed identical. The before build contains the switch entry
correction at `535d8c1deffce5745ac8f5dd80e1b2ae0b8d21d8`. The reference
scans were source only and had no compiled project classes, so these
results apply to the measured scopes.

The [regression fixture](../../crates/hoonarqube-java/tests/fixtures/LabeledContinueAndSuppression.java)
checks live writes before a plain `continue` with and without a switch and
before a named `continue` across two loops. It also distinguishes standard
and qualified suppression annotations, a positional warning array, an
unrelated warning, and named arguments. The before CLI had five extra
locations at lines 5, 16, 44, 51, and 53. The fixed CLI and a fresh Sonar scan
agree on all four remaining ranges:
`46:20–32`, `48:22–34`, `49:25–37`, and `55:18–30`.

The fresh fixture used Sonar Community Build 26.9.0.129388 with Java plugin
8.41 build 47177 and S1854 active. The successful analysis ID was
`df8cb28f-8ef5-428d-912b-cb54d25be13d`; the captured S1854 issue response
SHA-256 was
`81b3b3e3b02cf080dc81966a2be9953d1ba9f239f4b58391f901d6fc0e972315`.
No public project builds, tests, or applications were run.
