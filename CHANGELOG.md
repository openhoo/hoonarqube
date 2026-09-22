# Changelog

## 0.10.2 (2026-09-22)

### Bug Fixes

- **csharp:** anchor S121 else-alternative findings at the else keyword (#815) (fa4689d)
- **hoonarqube-ir:** bind finding identity to normalized path (#816) (e897643)

## 0.10.1 (2026-09-21)

### Bug Fixes

- **jsts:** stop JSX false positives in S6850, S6747, and S5254 (#808) (e6e1958)
- **hoonarqube-jsts:** cover explicit union returns, suppress ts S3800 (#809) (ff5f6e0)
- **jsts:** make S7060 self-import resolution extension-aware (#810) (92e9b9a)
- **jsts:** report one precise diagnostic for unsupported TypeScript compilers (#811) (0d84bbc)

## 0.10.0 (2026-09-21)

### Features

- **cli:** make sonar-parity machine-verifiable with report contract and reference comparison (#800) (21a2889)

### Bug Fixes

- **python:** count augmented parameter assignment as reading the initial value (#794) (5adea51)
- **csharp:** spare S1118 instance-state classes and locate S2629 template past logging metadata (#795) (06ccfa2)
- **jsts:** scope S3972 to adjacent sibling if statements and resolve S7060 by path (#796) (317d5f4)
- **jsts:** dedupe regex-site findings and align S5843 scoring with reference (#798) (1334fe9)

### Other Changes

- **oracle:** pin acceptance corpus for issue-797 linked regressions (#799) (e98dbc1)

## 0.9.2 (2026-09-21)

### Bug Fixes

- **analyzer:** honor inactive profile rules and explicit CSharp test scope (#785) (d0cb811)

## 0.9.1 (2026-09-21)

### Performance

- **hoonarqube:** optimize analyzer hot paths with measured parity (#783) (86d25b7)

## Unreleased

### Bug Fixes

- **hoonarqube:** stop `sonar-parity` from activating javascript/typescript
  S1441/S1537, python S1720/S6542, and csharpsquid S3216/S4261, which are
  absent from the reporter-exported SonarQube 2025.4.4 default "Sonar way"
  profiles; the cumulative recommended/extended/strict profiles keep every
  detector active (#780, #781, #782)
- **csharp:** keep MAIN-scope rules such as csharpsquid:S3216 suppressed on
  explicitly test-classified sources (#781)
- **oracle:** run the affected native all-rules comparisons under
  `--profile strict` and declare only the analyzed binary's exact registered
  `hoonarqube-*` keys as native findings in the comparator (#780, #781, #782)

### Performance

- Reuse C# node-kind indexing, Python source-snapshot facts and name lookups,
  JS/TS line-position/scanner work, and core source-facts/project bookkeeping
  without changing analysis outputs or resource-limit semantics.
- Qualify the local candidate against v0.9.0: 1.49x on the one-CPU reference
  corpus, 1.58x on its C# subset, and 1.24–1.25x on minified JS/TS workloads.
  Memory is broadly unchanged; see `PERFORMANCE.md` for measurements,
  unchanged/slower controls, methodology, and limitations.

## 0.9.0 (2026-09-20)

### Features

- **jsts:** add S7719, S7722, S7723, S7724, S7726 detectors for pinned anchors (#308) (dad91fe)
- **catalog:** add java and ruby sonar surfaces from community captures (#307) (7ba72d1)
- **python:** add S3415 S5778 S5779 S5863 S5958 test detectors (#154-#158) (#309) (ae685a9)
- **catalog:** add supplement mode for already-frozen catalog languages (#310) (a854095)
- **catalog:** supplement javascript and typescript S7719-S7726 keys from fresh capture (#311) (fc6151d)
- **python:** add S8502 S8510 S8513 S8714 S8786 reference detectors (#159-#163) (#313) (16604de)
- **jsts:** add S7737, S7741, S7744, S7746, S7751 detectors for pinned anchors (#314) (275e946)
- **catalog:** supplement javascript and typescript S7737-S7751 keys from fresh capture (#316) (1735995)
- **python:** add S8997 S9000 S9001 S9073 test detectors (#164-#167) (#317) (662115d)
- **jsts:** add S7754 S7755 S7765 S7766 S7770 detectors for pinned anchors (#320) (4fe72ed)
- **jsts:** add S7773 S7776 S7780 S7781 S7786 detectors for pinned anchors (#323) (78e50fb)
- **python:** add S9075 S9078 S9083 detectors, widen S2245, add py/file-not-closed (#324) (23cd6f7)
- **jsts:** implement four GitHub Code Quality detectors (#144-147) (#327) (c391c2c)
- **go:** register 17 catalog-claimed gcq quality queries (#422) (0af8393)
- **java:** register 15 single-file-provable gcq quality queries (#426) (b9d307d)
- **python:** add S1721 keyword-parentheses and S6538 return-type-hint coverage (#423) (fb92af5)
- **python:** add S8992 autouse+params fixture detector, supplement key (#361) (#430) (934c430)
- **java:** register 17 single-file-provable gcq quality queries (#429) (840ef50)
- **csharp:** close S2486/S3415 coverage, extend S1128/S3218/S2931 single-file subsets (#431) (96d4285)
- **ruby:** open sonar-parity route with ruby:S1192 duplicate-literal detector (#433) (4523678)
- **jsts:** add S7728 S7721 S5906 S7772 detectors with catalog keys (#436) (6d36f62)
- **csharp:** verify S1128/S3218/S2931 partials, extend six coverage-tail rules (#437) (ad4c6e6)
- **java:** open sonar-parity route with S1117 S1854 S2143 S2211 detectors (#438) (51474f2)
- **ruby:** add S1067 S126 S134 S1764 sonar-parity detectors (#440) (20b4879)
- **jsts:** add eight S77xx/S8754/S6437 detectors with catalog keys (#439) (7f3ebd2)
- **jsts:** add seven S77xx/S5914/S1244 detectors with catalog keys (#441) (2f630c9)
- **jsts:** add S7735 S8786 detectors with catalog keys (#442) (9b07fc9)
- **csharp:** add S8969 redundant null-forgiving detector with catalog key (#443) (d7ee2f2)
- **csharp:** close S1200 S3261 S2245 S6608 S1006 dapper false negatives (#444) (8eb55a6)
- **hoonarqube-jsts:** add S7763 S7767 detectors with catalog keys (#572) (22ba9d1)
- **python:** add S8994/S8998/S9074/S9076/S9077/S9084/S9116 detectors for catalog parity (#682) (#739) (2fec434)
- **python:** add S8492/S8495/S8500/S8507/S8509/S8512/S8514 detectors (#682) (#740) (5b0d51e)
- **python:** add S8517-S8521/S8554/S8572 idiom detectors for catalog parity (#682) (#741) (21a3087)
- **python:** add S7931/S7941/S7942/S7943/S7945/S8490/S8493/S8494 detectors (#682) (#742) (ec618a2)
- **python:** add S6965/S8401/S8412-S8415 web framework detectors (#682) (#743) (e1a6d93)
- **python:** add S8396/S8953/S8963/S8966/S8971/S8973 Pydantic detectors (#682) (#744) (ce6f84d)
- **python:** add S6863/S8370/S8371/S8374/S8375/S8385/S8400 web-framework detectors (#682) (#745) (a1fe6db)
- **python:** add S8389/S8397/S8405/S8409-S8411 FastAPI detectors (#682) (#746) (e529ff7)
- **python:** add S7618-S7622 AWS Lambda operational detectors (#682) (#747) (0bc23f1)
- **python:** add S7608/S7609/S7613/S7614/S7617 boto3/Lambda detectors (#682) (#748) (fb13c5a)
- **python:** add S8900/S8903-S8906 BeautifulSoup detectors (#682) (#750) (92d7c54)
- **python:** add S6243/S6246/S6249/S6262/S7625 AWS core detectors (#682) (#749) (0b23e4f)
- **python:** add S5976/S8993/S8999 pytest detectors (#682) (#751) (5d4e8af)
- **python:** add S8392/S8503-S8505/S8508/S8974/S8978 detectors (#682) (#752) (0760903)
- **python:** add S2187/S8511/S8515/S8516/S8685 detectors (#682) (#753) (366c2e6)

### Bug Fixes

- **javascript:** prevent SQL alias resolution stack overflows (#254) (1f1a21f)
- **csharp:** correct field visibility and readonly diagnostics (#256) (bb841c7)
- **go:** resolve receiver, flow, tag, and literal rule boundaries (#257) (7c7cdcc)
- **oracle:** reject non-hex repository revisions (#258) (0f843d1)
- **actions:** root nested-cwd reports and SARIF URIs (#141, #142) (#261) (8cbba3d)
- **agents:** bound issue work and persist verified handoffs (#263) (1645a6f)
- **assessment:** validate OpenCover hashes by file UID (#265) (e4846f0)
- **java:** preserve qualified constants interface identity (#266) (22d3f21)
- **rust:** resolve Rust rule-boundary defects and preserve typed trait identity (#262) (f654284)
- **python:** resolve imported IO exception ancestry (#267) (365cda8)
- **typescript:** detect safe object nullish alternatives (#268) (4ba2b63)
- **csharp:** preserve literal types when removing casts (#269) (0e437f8)
- **typescript:** reject unsafe nullish references and falsy BigInt (#271) (45d60b3)
- **assessment:** preserve baseline completeness and empty counts (#270) (29bc547)
- **java:** bind Javadoc parameter tags precisely (#273) (6cfef39)
- **python:** preserve comment and quickfix semantics (#272) (c67e91f)
- **csharp:** preserve live code when removing inline comments (#274) (14580cd)
- **jsts:** refuse symlinked helper writes and report missing compiler references (#275) (9df4ded)
- **export:** align Sonar and assessment lines with ECMAScript terminators (#276) (4e3cfcf)
- **python:** exclude docstrings from S1313/S5332 and accept tuple percent-formatting in S5607 (#278) (d9113bc)
- **java:** compose nested signature units structurally (#277) (b520c9b)
- **csharp:** preserve adjacent code and type identity in quickfix removals (#279) (13e9d6a)
- **python:** model definition contexts for S5720 and S5722 (#280) (5dcd9f2)
- **jsts:** refuse unsafe S1125 constant folds and group S1940 inversions (#281) (5ec2115)
- **ruby:** tie uninitialized-receiver guard reasoning to the receiver binding (#282) (123cd87)
- **csharp:** score static locals separately and pair hidden base methods by signature (#284) (28a4ab1)
- **jsts:** resolve alias provenance and nested-chain identities for S6571, S1523, and S1871 (#285) (11a565d)
- **python:** gate S6795 on real aliases and honor S905 reportOnStrings (#283) (2bc86df)
- **csharp:** exempt initializers, interface signatures, and increment reads (#288) (c0f1000)
- **ruby:** stop receiver, join, and indexed-key local-flow false positives (#286) (d71ecd0)
- **python:** complete shared traversal and rebinding events for S1523 (#289) (9609c2b)
- **jsts:** close regex-literal and proto ownership false negatives (#290) (60ed6fe)
- **java:** treat enum constant bodies as distinct declaring types (#291) (be65a73)
- **metrics:** normalize both sides of new-code inventory joins (#292) (e416e87)
- **python:** close store, unused-name, and complexity false negatives (#293) (a38bb5b)
- **csharp:** resolve S6966 receivers, S1939 arity, partial shadows, and coalescing writes (#294) (f9b88f5)
- **cli:** enforce the source-size bound before reading whole sources (#295) (608fca4)
- **jsts:** parse TypeScript variance modifiers for complete source facts (#296) (13cfad7)
- **python:** report aliased typing forms, parameter shadows, and comment-insensitive duplication (#298) (4f38559)
- **jsts:** parse JSX natively, scope census, honor labels, report branch dead stores (#301) (8bc03c4)
- **python:** repair module scope, override, complexity, and literal rules (#300) (e5293f1)
- **python:** propagate S5797 local constants and accept tab escapes in S5856 classes (#303) (9c6567b)
- **jsts:** report S905 member reads, S6582 negated-OR guards, S4138 indexed loops, S6557 indexes (#304) (d599f3a)
- **jsts:** report S6666 nonliteral apply arrays and S2486 multi-statement catches (#252, #253) (#305) (50fabbb)
- **deps:** update rustls to 0.23.45 for RUSTSEC-2026-0285 (#319) (3850245)
- **rust:** exempt non-logging S106 contexts, cross-crate enum globs, align S4275/S3776 with Sonar (#411) (f94fa6b)
- **csharp:** recover preprocessor directives failing the whole parse (#328) (#412) (6eb620c)
- **python:** match reference semantics for six real-world FP rules (#351-#356) (#413) (a5f5088)
- **java:** bound anonymous declaring types and decode escape-tail concatenation (#416) (790fa04)
- **jsts:** align S1472 S109 S1192 S3798 S3827 with Sonar semantics (#414) (5f839d5)
- **go:** silence MAIN-scope rules on test files, charge literal complexity to encloser (#415) (0d1651c)
- **cli:** substitute $@ flow names in GitHub Code Quality SARIF messages (#417) (765d92d)
- **python:** silence MAIN-scope rules on tests, resolve library exception hierarchies (#420) (a56255d)
- **ruby:** stop uninitialized and dead-store regressions from block, binary, and loop shapes (#419) (898788a)
- **csharp:** match reference semantics for five real-world FP rules (#329-#333) (#418) (0402715)
- **jsts:** align S2999 S4144 S2376 S4275 S6435 S6441 S6746 with Sonar semantics (#421) (0887227)
- **csharp:** align five real-world FP rules with reference semantics (#424) (94fed4a)
- **jsts:** close S1537 S1539 S2138 S6582 gaps, exclude .d.ts files (#382-#386) (#425) (4cbb606)
- **jsts:** restore reference semantics for S3512 S7773 S5958 S3498 false negatives (#427) (9a538ab)
- **csharp:** align S2479 S4581 and catalog MAIN scope with reference semantics (#428) (dd3f20e)
- **jsts:** align S139 S122 S2486 with pinned SonarQube semantics (#391-#393) (#432) (82c3c79)
- **csharp:** prefer attribute target specifier in vendored grammar (#435) (e9d6577)
- **csharp:** bind interface impls and base-class state for S1694 S4019 (#434) (7b9af5a)
- **hoonarqube-jsts:** close statement and switch-flow rule gaps (#562) (69f24f2)
- **hoonarqube-jsts:** twelve tier_b rule fixes for S1537/S3723/S1854/S2933/S1117/S2589/S4623/S930 (#563) (f62f0a2)
- **jsts:** ungate compiler-backed TS rules and fix S4782 exactOptionalPropertyTypes FP (#564) (7bdd8d8)
- **hoonarqube-go:** align 17 rules with SonarGo semantics and parse Go 1.26 new(expr) (#565) (5b16775)
- **hoonarqube-jsts:** batch2d rule fixes for S4275/S3358/S3498/S3499/S6582/S1534/S3973 (#566) (99027b5)
- **hoonarqube-jsts:** expression FP fixes (S1763/S1110/S1440/S3524/S2871) (#567) (c5cb159)
- **hoonarqube-jsts:** batch2d S1067/S1541/S3776/S3801/export-default parity (#568) (4eda871)
- **hoonarqube-jsts:** align batch5 rules with upstream contracts (#569) (3907363)
- **hoonarqube-jsts:** align S134/S878/S881/S1121/S135/S1535 with upstream (#570) (3336427)
- **hoonarqube-jsts:** return-shape facts fix S3699/S3800/S4123 FPs (#571) (e7f702c)
- **hoonarqube-jsts:** misc FP fixes (S6478/S6643/S4823/S1515/S125/S3533/S2138) (#573) (ea6d213)
- **hoonarqube-jsts:** misc rule parity fixes (S7721/S7755/S7781/S1441/S117/S138/S7722/S1105/S105/S1764) (#574) (9069c60)
- **hoonarqube-jsts:** S2814/S3353/S1451/S1438 detectors, HTML script extraction, hotspot routing (#687) (8b495dd)
- **python:** accept control-character escapes in regex parser (S5856) (#686) (098c316)
- **python:** align naming and unused-parameter rules with Sonar exemptions (#688) (66b54fa)
- **python:** extend security sink coverage to match Sonar (#690) (297efc2)
- **python:** align statement-level rules with Sonar semantics (#689) (1ba59e3)
- **python:** extend misc rule coverage to match Sonar (#691) (fc44e0a)
- **python:** align counting rules with Sonar semantics (#697) (15fe4ae)
- **python:** align block/comment/import rules with Sonar exemptions (#693) (d7e9b63)
- **python:** align signature and contract rules with Sonar exemptions (#695) (4311ac1)
- **python:** align literal and format rules with Sonar exemptions (#696) (e2925bf)
- **python:** align liveness and CFG rules with Sonar semantics (#694) (56ba7bb)
- **python:** exempt async copy-only comprehensions (#698) (7f8621d)
- **python:** align regex backtracking and alternation rules with Sonar semantics (#692) (3617525)
- **python:** restrict nullable string fields to Django models (#699) (4fed0a6)
- **python:** restrict constant dictionary comprehension suggestions (#700) (2cd13ea)
- **python:** distinguish scalar float equality from nested values (#701) (8070934)
- **go:** exempt single-line switch bodies from duplicate checks (#702) (2f5e301)
- **python:** require docstrings on non-method dunder functions (#703) (4cd70a4)
- **python:** restrict nesting depth findings to main sources (#704) (f2f8015)
- **python:** align cleartext checks with literal token boundaries (#705) (b015ae2)
- **python:** restrict composite assertion scope to test contexts (#707) (29adc2c)
- **python:** resolve S6554 inherited __str__ through project context (#708) (302808b)
- **python:** align function complexity counting with reference semantics (#706) (1774776)
- **python:** scope S6660 type comparisons to per-pair ==/!= operands (#709) (ac88930)
- **python:** flag S5709 on forbidden exception bases regardless of class name (#710) (2b86fe6)
- **python:** flag negated in/is comparison chains Sonar still reports in S1940 (#711) (477aefe)
- **python:** align S1764 identical-operand checks with Sonar operator and exemption semantics (#712) (6c974dd)
- **python:** pin S6709 stdlib random exemption with regression test (#713) (1259d16)
- **python:** align S2737 re-raise detection with Sonar ExceptRethrowingCheck (#714) (7302cd4)
- **python:** exempt S1700 classes with arguments except sole object base (#715) (fab1944)
- **python:** pin S1656 class-body and imported-name exemptions with regression test (#718) (0b86441)
- **python:** pin S3330 non-literal httponly compliance with regression test (#618) (#719) (0fbe7e8)
- **python:** exempt S1515 lambdas taking the loop variable as a parameter (#722) (b0bc139)
- **python:** exempt S5807 __all__ entries under module-level __getattr__/__dir__ (#723) (caaf8f9)
- **python:** scope S4507 to Sonar framework debug entry points (#728) (d68c55e)
- **python:** extend S8502 provable-set check to annotated receivers (#639) (#729) (5fe4fa2)
- **python:** exempt S5899 methods referenced inside the TestCase class (#647) (#736) (4c37c01)
- **python:** complete S7504 mutation exemption and cover comprehensions (#737) (dcd0b41)
- **hoonarqube-catalog:** supplement 89 python rules from CE 26.8 capture (#682) (#754) (3f0b0ff)
- **service,core,ci,tools:** six verified bug fixes from the 2026-09-20 review (#775) (c798e97)
- **python,ruby:** six detector fixes from the 2026-09-20 review (#776) (d88a34c)
- **jsts:** refuse unsafe S1488/S4623 quickfixes and preserve S1125 precedence (#777) (97b572a)
- **csharp:** refuse unsafe quickfixes for S1939/S3240/S3254/S3440/S3604 (#778) (b3d3558)

### Performance

- **hoonarqube:** reduce profile runtime and report footprint (3b3c642)

### Other Changes

- integrate agent issue workflow (#235) (6c274a2)
- **hoonarqube:** require PR templates and regression coverage (#255) (3b1b1fa)
- **actions:** fix immutable action revision (#264) (23ac99e)
- **security:** document quality-only GitHub Code Quality boundary (#148, #149, #175) (#306) (e531483)
- **catalog:** supplement python S3415 S5778 S5779 S5863 S5958 keys (#312) (e8ca26a)
- **catalog:** supplement python S8502 S8510 S8513 S8714 S8786 keys (#159-#163) (#315) (3cc1145)
- **catalog:** supplement python S8997 S9000 S9001 S9073 keys (#164-#167) (#321) (338fb6f)
- **catalog:** supplement javascript and typescript S7754-S7770 keys from fresh capture (#322) (ed0dae3)
- **catalog:** supplement javascript and typescript S7773-S7786 keys (#325) (fee4375)
- **catalog:** supplement python S9075 S9078 S9083 keys (#168-#170) (#326) (b7a22e7)
- reconcile documentation with current analyzer truth (#575) (4163d20)
- **python:** pin S6542 bare-Any semantics against nested generic annotations (#716) (b4eaa7d)
- **python:** pin S5724 required-parameter counting on property getters (#717) (2f1ad8b)
- **python:** pin S1721 single-element tuple exemption (#720) (b2c832d)
- **python:** pin S1707 unanchored person-reference exemption on issue 632 (#721) (d45d15c)
- **python:** pin S2257 bitwise-XOR helper exemption for issue #634 (#724) (aaaa7be)
- **python:** pin S3358 comprehension exemption for nested conditionals (#635) (#725) (2df8603)
- **python:** pin S3981 adjacent-pair chained comparison semantics (#636) (#726) (38cff18)
- **python:** pin S5747 except-called-function bare-raise exemption (#637) (#727) (fa62ea5)
- **python:** pin S2733 varargs __exit__ signature acceptance (#640) (#730) (c26832b)
- **python:** pin S5719 *args positional-parameter exemption (#644) (#731) (b716b17)
- **python:** pin S7513 spawned-task counting against loop call sites (#650) (#733) (4761f34)
- **python:** pin S5344 credential-named SQL template exemption (#643) (#732) (2b3540d)
- **python:** pin S7492 any/all call-expression anchor (#674) (#734) (7bd5798)
- **python:** pin S5797 literal while-condition exemption (#645) (#735) (3836ce9)
- **python:** pin S2201 Sonar pure-function allowlist on issue 675 repro (#738) (14dc937)

## 0.8.2 (2026-09-11)

### Bug Fixes

- **hoonarqube:** harden analysis boundaries and quick fixes (e7add58)

## 0.8.1 (2026-09-10)

### Bug Fixes

- **hoonarqube:** qualify remaining parity and guarded fixes (e71a7e6)

## 0.8.0 (2026-09-10)

### Features

- **hoonarqube:** complete analysis capabilities and evidence boundaries (d6048e6)

## 0.7.1 (2026-09-09)

### Bug Fixes

- **hoonarqube:** correct real-project analyzer findings (#84) (cf6a668)

## 0.7.0 (2026-09-08)

### Features

- **cli:** cache unchanged file analysis (#33) (036baa2)

## 0.6.0 (2026-09-08)

### Features

- **cli:** add native GitLab Code Quality reports (a47fcf7)

## 0.5.1 (2026-09-08)

### Performance

- **hoonarqube:** optimize duplication coverage and benchmark scaling (3dd0d68)

## 0.5.0 (2026-09-08)

### Features

- **hoonarqube:** add project metrics and duplicate-code detection (#27) (a515757)

### Bug Fixes

- correct analyzer data flow and oracle validation (#24) (d305104)

## 0.4.2 (2026-09-04)

### Performance

- **hoonarqube:** parallelize file analysis (#22) (48d89b5)

### Other Changes

- **release:** add immutable asset recovery (#21) (82a1f39)

## 0.4.1 (2026-09-04)

### Bug Fixes

- **hoonarqube:** harden CodeQL parity and validation (#19) (50ca924)

## 0.4.0 (2026-09-04)

### Features

- **github-quality:** add CodeQL analysis profile (#15) (90357d9)

### Bug Fixes

- **hoonarqube:** align GitHub CodeQL parity (68058d3)
- **release:** repair version synchronization (4b01d0a)

## 0.3.1 (2026-09-03)

### Bug Fixes

- **analyzers:** harden language semantics (0074f69)

### Other Changes

- **ci:** update Hoostack tool pins (9e13ab1)
- **ci:** pin HooNeedsUpdates to v0.3.0 (#12) (887c2a9)

## 0.3.0 (2026-09-01)

### Features

- **analyzer:** add native quality profiles (#7) (d87bb03)

### Bug Fixes

- **release:** recover protected branch finalization (#9) (98c0975)

## 0.2.4 (2026-08-31)

### Bug Fixes

- align Hoostack policy and release supply chain (#4) (e53f772)
- **release:** honor protected main branch (d59fb05)

## 0.2.3 (2026-08-30)

### Bug Fixes

- **security:** harden oracle scanner workspace (#3) (c3a90d3)

## 0.2.2 (2026-08-30)

### Bug Fixes

- **release:** upload only release files (86333e4)

### Other Changes

- standardize Hoostack dogfood (1f0a8ae)

## 0.2.1 (2026-08-30)

### Bug Fixes

- harden analyzers and clear code smells (94560de)
- **cli:** make Hoostack dogfood reliable (b00cbc5)

### Other Changes

- use released Hoostack actions (75fcca7)
- test pull request head commits (cb93963)

## 0.2.0 (2026-08-29)

- Harden analyzer behavior, verified quick fixes, parity evidence, and oracle failure handling.

## 0.1.0 (2026-08-28)

- Publish initial frozen-catalog analyzers for Python, JavaScript/TypeScript, C#, Go, and Rust.
