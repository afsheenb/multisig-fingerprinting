# Provider attribution report

Generated from registry version 2026-10-18 over the in-study corpus (heights 812688..972009, 75707 revealed scripts). All figures are RAW COUNTS over the sampled corpus, not population estimates.

## Interpretation rules (apply to every number below)
- A shared script template NEVER implies shared ownership. Templates are structural shapes; unrelated wallets converge on the same shapes.
- Shared pubkeys link SCRIPTS, not people. A key appearing in two scripts establishes exactly that byte-level relationship.
- Grade B confirms a KEY'S PARTICIPATION in a script, never wallet ownership: a provider-published key inside a script proves the key is there, not who controls the wallet.
- The false-positive rate for every grade below is UNKNOWN: there is no labeled held-out data. Grades C and D are implementation matches, not attributions of a wallet to an operator.
- Grade E means the registry contains no matching structure; it does not mean the script has no provider.
- Control-group matches (Lightning, Liana, Specter, generic BIP67) are by definition NOT provider attributions; they exist to quantify how weak the template-only signal is.

## Headline: how much of the corpus is attributable, at what grade

| Grade | Scripts | Percent of 75707 |
|---|---|---|
| A: verified provider attribution | 0 | 0.00% |
| B: verified institutional key participation | 0 | 0.00% |
| C: strong implementation match | 430 | 0.57% |
| D: weak implementation match | 30439 | 40.21% |
| E: unknown | 44838 | 59.23% |

## The zero-A statement

Grade A requires independent evidence tying a wallet or transaction to a provider: a first-party disclosure, an authenticated descriptor, or a verified mainnet txid. The registry carries NO mainnet txids, so the A rule cannot fire and 0 A rows is the correct result, not a failure of the engine. The rule is implemented (provider known_txids joined against corpus transactions) and will produce A rows the moment a provider-published txid enters the registry.

## The unknown-false-positive statement

Every match grade below A is reported with an UNKNOWN false-positive rate. There is no labeled held-out corpus in this study: no set of scripts with ground-truth provider labels exists to measure how often a C or D match is wrong. The control groups are the substitute: they bound how often the same shapes arise for reasons unrelated to any provider, and the contamination table below applies that bound. Percentages of the corpus attributed at C or D must be read as implementation-match ceilings, not attribution counts.

## Grade B: the Green service key result

The registry carries exactly one provider-static mainnet pubkey (Green's legacy v0 service key 0322c5f5c9c4b9d1...) plus documentation/demo xpubs for BitGo, Unchained and Nunchuk (checked as their xpub-derived root keys; deriving children without published paths would be guessing). The Green service pubkey appears in 0 of the 75707 in-study scripts, so grade B fires 0 times. A B match would have confirmed only the key's participation, not wallet ownership; that caveat is recorded per row regardless.
- Registry entries that are not script keys and so cannot appear in scripts (checked, zero matches possible): blockstream_green e9a563d68686... (mainnet legacy v0 service chain code paired with the service)
- Graph export note: 51 reused keys exceed the 1000-pair cap for the scripts_share_key edge list (3077401 pairs omitted in total); their key_in_script edges are complete.

## Per-provider breakdowns

Providers and control groups with at least one A-D match. C and D are implementation-match grades. control-explained = the same script also matches a control-group row at equal or better grade.

| Provider | Control | A | B | C | D | ambiguous | control-explained |
|---|---|---|---|---|---|---|---|
| onramp (Onramp) | no | 0 | 0 | 0 | 26208 | 26202 | 6775 |
| bitgo (BitGo) | no | 0 | 0 | 0 | 19529 | 19427 | 0 |
| nunchuk (Nunchuk) | no | 0 | 0 | 0 | 11071 | 11071 | 3748 |
| casa (Casa) | no | 0 | 0 | 0 | 8886 | 8864 | 1623 |
| blockstream_green (Blockstream Green) | no | 0 | 0 | 430 | 7830 | 7241 | 0 |
| unchained (Unchained (formerly Unchained Capital)) | no | 0 | 0 | 0 | 6775 | 6775 | 6775 |
| specter_diy (Specter DIY (specter-desktop, control group)) | yes | 0 | 0 | 0 | 5371 | 5371 | 0 |
| lightning_channel_funding (Lightning channel funding output (control group)) | yes | 0 | 0 | 0 | 3518 | 0 | 0 |
| generic_bip67_multisig (Generic BIP67 sorted multisig (control group)) | yes | 0 | 0 | 0 | 1404 | 1404 | 0 |

## Ambiguity report

26202 scripts carry an ambiguity flag: more than one provider remains plausible at the script's best grade, and every candidate is recorded with the flag instead of picking one.
- 00018d2d499b0a93 grade D: bitgo (D), blockstream_green (D), casa (D), onramp (D)
- 00051ce627727a04 grade D: bitgo (D), blockstream_green (D), casa (D), onramp (D)
- 000682653ca38503 grade D: nunchuk (D), onramp (D), specter_diy (D), unchained (D)
- 0006f83c929d4468 grade D: nunchuk (D), onramp (D), specter_diy (D), unchained (D)
- 0007bcf41e81c2c9 grade D: bitgo (D), nunchuk (D), onramp (D)
- 000a7e8a46536de0 grade D: casa (D), onramp (D), specter_diy (D), unchained (D)
- 000c12b4187fc036 grade D: casa (D), onramp (D), specter_diy (D), unchained (D)
- 000f3624dff2eed2 grade D: nunchuk (D), onramp (D), specter_diy (D), unchained (D)
- 001067120ef7c8f2 grade D: bitgo (D), blockstream_green (D), casa (D), onramp (D)
- 001070f3bea804d7 grade D: bitgo (D), blockstream_green (D), casa (D), onramp (D)
- (first 10 of 26202 shown; the full set is in reports/attribution_matches.json)

## Control-group contamination

How many C/D provider matches are equally explained by a control group (a control row matches the same script at equal or better grade):
- C matches by non-control providers: 430, of which control-explained: 0
- D matches by non-control providers: 80299, of which control-explained: 18921
The sorted 2-of-3 shapes are the worst case: the generic BIP67 control row is feature-identical to the Unchained, Specter and Casa rows, so nothing in the observable features separates a provider wallet from DIY or exchange cold storage on those shapes.

## What the corpus cannot support (missing edges)

The study spec lists edge types this corpus cannot produce. They are listed here instead of faked:
- signature_provided per key: witness signature-to-key mapping exists only for locally resolvable prevouts (249 of 161,202 script-revealing observations); the raw-transaction endpoint is soft-blocked (confirmed txids answer HTTP 200 with empty data, docs/api_notes.md), so per-key signature edges cannot be built at corpus scale.
- same scriptPubKey outputs and spends: prevout resolution is unavailable on the no-key tier; the corpus resolves only cached prevouts, so reuse of the same scriptPubKey and spend-graph edges are unobservable.
- xpub derivation to corpus keys: the provider xpubs in the registry are API-verification keys and documentation/demo fixtures. Deriving child keys to hunt corpus matches requires provider-published derivation paths, which do not exist; guessing paths is excluded by the study rules.
- verified wallet attribution: no provider publishes txids or address sets, so the A-grade edge cannot exist yet.

Coverage note: the registry records only Green's optimized CSV layout. The libwally non-optimized CSV 2-of-2-then-1 layout documented in docs/provider_research.md has no registry row, so timelocked_singlesig_recovery scripts in other layouts are unmatched by design. Extending the registry is a research step, not an engine step.

## Same-shape buckets (necessary, not sufficient)

Every script that ends at grade E or in an ambiguity group is bucketed by (template_l3, threshold, n_keys, keys_sorted, source, sorted timelock values). Buckets are a same-PROVIDER hypothesis generator only: one provider with per-wallet keys splits into many buckets, and generic shapes merge unrelated providers into one bucket. 1853 buckets exist in total; every one is exported with size, distinct key count, height span and registry-match status in reports/attribution_buckets.json. Top 15 by size:

| n_scripts | source | template | k/n | sorted | CSV values | distinct keys | seen | registry match |
|---|---|---|---|---|---|---|---|---|
| 22884 | taproot_leaf | <P> OP_CHECKSIG <D> OP_IF <D> <D> <D> <D> <D> OP_ENDIF | None/1 | n/a | - | 20770 | 812688..971251 | no |
| 14564 | p2wsh_witness | OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG | 2/3 | no | - | 43556 | 812688..971251 | yes: bitgo, blockstream_green, casa, nunchuk, onramp |
| 5371 | p2wsh_witness | OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG | 2/3 | yes | - | 15968 | 812688..971251 | yes: casa, nunchuk, onramp, unchained, specter_diy |
| 4863 | p2sh_redeem | OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG | 2/3 | no | - | 14558 | 812688..971251 | yes: bitgo, onramp |
| 3838 | p2wsh_witness | OP_1 <P> OP_1 OP_CHECKMULTISIG | 1/1 | yes | - | 3838 | 812688..971251 | no |
| 3155 | taproot_leaf | <P> OP_CHECKSIG <D> OP_IF <D> <D> <D> OP_ENDIF | None/1 | n/a | - | 861 | 812688..969769 | no |
| 1462 | p2wsh_witness | OP_3 <P> <P> <P> <P> OP_4 OP_CHECKMULTISIG | 3/4 | yes | - | 5848 | 812688..971251 | no |
| 1404 | p2sh_redeem | OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG | 2/3 | yes | - | 4132 | 812688..971251 | yes: onramp, unchained, generic_bip67_multisig |
| 1190 | p2wsh_witness | OP_2 <P> <P> OP_2 OP_CHECKMULTISIG | 2/2 | no | - | 1860 | 812688..971251 | no |
| 939 | p2wsh_witness | OP_2 <P> <P> OP_2 OP_CHECKMULTISIG | 2/2 | yes | - | 1178 | 812688..965365 | no |
| 591 | taproot_leaf | <P> OP_CHECKSIG <D> OP_IF <D> <D> <D> <D> <D> <D> <D> OP_END | None/1 | n/a | - | 585 | 814374..971251 | no |
| 526 | p2wsh_witness | OP_2 <P> <P> <P> <P> OP_4 OP_CHECKMULTISIG | 2/4 | yes | - | 1847 | 814374..971251 | no |
| 525 | p2wsh_witness | <P> OP_SWAP <P> OP_CHECKSIG OP_IF OP_SWAP OP_DUP OP_HASH160  | None/2 | n/a | [1008] | 1050 | 814663..970425 | no |
| 474 | taproot_leaf | <P> OP_CHECKSIG <D> OP_IF <D> <D> <D> <D> <D> <D> OP_ENDIF | None/1 | n/a | - | 470 | 814374..955719 | no |
| 423 | taproot_leaf | <P> OP_CHECKSIG <D> OP_IF <D> <D> <D> <D> <D> <D> <D> <D> OP | None/1 | n/a | - | 422 | 814374..935207 | no |

## Owner refinements

### AnchorWatch negative filter and CSV day-hint

Negative filter: AnchorWatch is P2WSH miniscript and explicitly not taproot, so NO taproot_leaf-source script can be AnchorWatch. The engine enforces this through the row's form (p2wsh): every taproot_leaf script is excluded from AnchorWatch matching by construction, and its candidates are p2wsh_witness-sourced multisig/conditional structures only.

CSV day-hint: AnchorWatch publishes recovery delays in calendar days (335 and 380); CSV is denominated in blocks. At the 144 blocks/day convention the hints are 48,240 and 54,720 blocks. Histogram of CSV values over in-study scripts (all sources, then p2wsh_witness only):

| CSV blocks | scripts (all) | scripts (p2wsh) |
|---|---|---|
| 1008 | 610 | 536 |
| 51840 | 400 | 400 |
| 4032 | 126 | 126 |
| 4320 | 81 | 80 |
| 144 | 66 | 64 |
| 288 | 40 | 40 |
| 25920 | 28 | 27 |
| 65535 | 24 | 24 |
| 2016 | 18 | 18 |
| 4210841 | 14 | 13 |
| 4212022 | 13 | 13 |
| 1201 | 9 | 9 |
| 240 | 9 | 9 |
| -662110079 | 6 | 6 |
| 4195485 | 6 | 0 |

Result: 0 scripts at 48,240 and 0 at 54,720; no value within 3 days (432 blocks) of either hint (empty neighborhood). The dominant values (1008 = 1 week, 4032/4320 = 4 weeks, 144 = 1 day, 25920/51840 = Green's buckets, 65535) are standard conventions, not day-conversion artifacts. No AnchorWatch day-hint upgrade fires: the evidence is a null result either way, and the histogram is recorded as the check.

### Onramp cosigner-key cross-reference

Onramp's documented 2-of-3 quorum is structurally identical to plain BitGo's unsorted positional 2-of-3, so template alone cannot separate them; the separator would be a recurring institutional key. Keys appearing in 5+ distinct unsorted 2-of-3 scripts:

| key | distinct unsorted 2-of-3 scripts | distinct templates | first seen | last seen |
|---|---|---|---|---|
| 033f67b4653f6f60081c649081c5626c1d4bf03f6b9f092a713558d29cdbf64987 | 64 | 1 | 814374 | 969769 |
| 02ba60b798675989b4db608dff11f3c7e2204d20ddaee331a84a5f86a5cf1d4554 | 36 | 1 | 848088 | 848088 |
| 02e5683b73c8713394189ee7a8441ab7268d43ac5a55ea9890eb92947b48a4ffa9 | 36 | 1 | 848088 | 848088 |
| 03a553e30733d7a8df6d390d59cc136e2c9d9cf4e808f3b6ab009beae68dd60822 | 32 | 1 | 812688 | 971251 |
| 027072ba2319ead2b0b387d69d36508f57b397da8d4ac76ea64676ee8a1356dae0 | 6 | 1 | 896014 | 896014 |
| 02f39d0b69c3b8e06030ef9dc295cf8c848f51e398fe85414e33509afdc7f01fb3 | 6 | 1 | 896014 | 896014 |
| 0352d50656796dd79e3e3385c29636d849b8705c9c6d9b86a1717adc38e4a567c7 | 6 | 1 | 896014 | 896014 |

These are CANDIDATE institutional keys, grade B pending authentication: no registry entry authenticates any of them, so they raise no script above its current grade and generate no attribution edge. Keys recurring across the whole study window with a single template are the strongest same-implementation signal the corpus can produce without a provider-published key.

## What would change this report

- Index or paid API access for prevout resolution: same-scriptPubKey reuse and spend-graph edges become observable, and deposit-side visibility stops being one-sided; signature-to-key edges scale beyond the 249 locally resolvable observations.
- Provider-published descriptors, addresses or txids: any single published txid or address set converts the affected scripts to grade A and turns this report's C/D ceiling into verified attribution.
- Per-provider key disclosure (as Green did for its v0 service key): each disclosed static key adds grade-B participation edges across every script containing it, the strongest evidence class this corpus can carry.
