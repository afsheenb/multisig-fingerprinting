# Preliminary findings (pilot corpus)

Generated 2026-10-18 15:43 UTC. **Scope: sampled corpus, heights 812688..972009.** All statistics below are RAW COUNTS over the sampled blocks, not population estimates and not extrapolations.

## Interpretation rules (apply to every number below)
- A shared script template NEVER implies shared ownership. Templates are structural shapes; unrelated wallets converge on the same shapes.
- Shared pubkeys link SCRIPTS, not people. A key appearing in two scripts establishes exactly that byte-level relationship; it says nothing about who controls the keys.
- No provider attribution appears in this report. Attribution requires independently verified evidence, which the corpus does not carry.
- Taproot key-path spend counts are an opaque control population. MuSig2 adoption is NOT measurable from them: a key-path spend could be single-key or an aggregate, and the output key reveals neither.
- A revealed script was knowable only from its spend. Deposit-side visibility is not claimed: most revealed scripts were never spent inside the sampled blocks, so corpus counts are floors, not totals.

## Coverage
- Blocks scanned: 180 in-study (heights 812688..972009)
- Footnote: block 811800 sits outside the study window and is kept only as an acquisition smoke test; it is EXCLUDED from every count below.
- Transactions examined: 612566
- Inputs examined: 1296043
- Revealed scripts (deduplicated): 75707 across 161202 spend observations
- Distinct public keys: 138294; keys in 2+ distinct scripts: 1259
- Key-reuse components (union-find over exact-byte shared keys): 20; largest: 20 keys/2 scripts, 16 keys/2 scripts, 9 keys/70 scripts, 8 keys/4 scripts, 7 keys/241 scripts

## Input forms
- p2wpkh: 790237
- taproot_keypath: 211684
- legacy: 126602
- taproot_scriptpath: 104910
- p2wsh: 29186
- p2sh_p2wsh: 17890
- p2sh_redeem: 9216
- other: 6318

## Script sources
- p2sh_redeem: 6638
- p2wsh_witness: 37729
- taproot_leaf: 31340

## Wallet families (L4, structural buckets only)
- standard_multisig: 39061
- taproot_conditional_recovery: 30083
- timelocked_singlesig_recovery: 4632
- taproot_scriptpath_other: 928
- conditional_policy: 422
- taproot_scriptpath_multisig: 279
- timelocked_recovery_multisig+conditional_multisig: 136
- hashlock_policy: 54
- taproot_unknown: 50
- sigscript_policy: 43
- conditional_multisig: 19

## Most common parameter-normalized templates (L3, pure n-of-n multisig classes; compound and taproot script-path policies are bucketed under families instead)
- 26202x `OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIG`
- 6361x `OP_2 <P> <P> OP_2 OP_CHECKMULTISIG`
- 3839x `OP_1 <P> OP_1 OP_CHECKMULTISIG`
- 1576x `OP_3 <P> <P> <P> <P> OP_4 OP_CHECKMULTISIG`
- 527x `OP_2 <P> <P> <P> <P> OP_4 OP_CHECKMULTISIG`
- 248x `OP_1 <P> <P> OP_2 OP_CHECKMULTISIG`
- 153x `OP_3 <P> <P> <P> <P> <P> OP_5 OP_CHECKMULTISIG`
- 41x `OP_5 <P> <P> <P> <P> <P> <P> <P> OP_7 OP_CHECKMULTISIG`
- 24x `OP_2 <P> <P> <P> <P> <P> OP_5 OP_CHECKMULTISIG`
- 21x `OP_5 <P> <P> <P> <P> <P> <P> OP_6 OP_CHECKMULTISIG`
- 18x `OP_3 <P> <P> <P> <P> <P> <P> OP_6 OP_CHECKMULTISIG`
- 15x `OP_1 <P> <P> <P> OP_3 OP_CHECKMULTISIG`
- 6x `OP_2 <P> <P> <P> OP_3 OP_CHECKMULTISIGVERIFY <D> OP_DROP OP_DEPTH <D> OP_EQUAL`
- 6x `OP_2 <P> <P> <P> <P> <P> <P> OP_6 OP_CHECKMULTISIG`
- 5x `OP_4 <P> <P> <P> <P> <P> <P> OP_6 OP_CHECKMULTISIG`

## BIP67 sorting
- unsorted: 21439
- sorted: 17619

## Example transactions
- p2sh_redeem: c7d3315da094b60caf25e9a6dc4f115be634ac3de0dd7bc46066cb0aaf74214a input 0 (block 971251)
- p2wsh: 2da553350199d67948a2083daac3f7050ead7c33fb8e07ed198d8b5a4154a90b input 0 (block 971251)
- p2sh_p2wsh: f1fea383111deb64b9c4cb0046962dccb6c53fb2aaa00c2f87c4516e150b5669 input 0 (block 971251)
- taproot_scriptpath: 0df2c76bee5bbe220fa84e2eba6ba60e0c8c8fbb9b74bb6eaed7e68d3a3fbdfb input 0 (block 971251)
- taproot_keypath: 587fa5e18c4ee7229ec3efe17ba464b226e1fb96333c452f454da854a55bf1c4 input 0 (block 971251)

## Local cryptographic validation (zero points)
- Inputs checked against cached prevouts: 249 of 161202 script-revealing observations (the rest have no prevout in the sampled corpus)
- Commitments: 27 verified, 0 FAILED, 222 not verifiable (taproot output-key binding needs the taptree)
- Signatures: 58 of 58 present signatures verify under BIP143 sighash + ECDSA (corpus-resolvable inputs only)

## Limitations
- Signature/commitment verification covers only corpus-resolvable prevouts (the /bitcoin/raw/transaction endpoint is soft-blocked on the no-key tier: confirmed txids answer HTTP 200 with empty data; evidence in docs/api_notes.md). The 1.3M-input corpus resolves only a small subset locally.
- Taproot output-key binding is not_verifiable without taptree data: a revealed leaf proves the script existed in the tree, not that the output key commits to it (internal-key hiding means it usually does not, visibly).
- Key-reuse matching is exact-byte only. Case-2 reuse (the same scriptPubKey spent again) is not observable without prevout resolution, so reuse counts are lower bounds.
- Sample: 180 in-study blocks out of the 159,322-block study period (heights 812688..972009), a ~0.11% sample. Every figure here is a raw count over that sample.
- Deposit-side coverage is one-sided: scripts are revealed only when spent inside a sampled block; unspent and spent-outside-sample policies are invisible.

## Spot checks
- 3 of 3 sampled revealed scripts re-derived from the cached raw block JSON (block decode -> input classification -> script extraction -> analyze_script) reproduce the stored classification, keys, templates, and thresholds exactly; script_sha256 matched in every case. Seed 20261018; per-field detail in reports/spot_checks.json.
