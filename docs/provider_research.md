# Provider script-structure research (public sources only)

This document backs `registry/providers.json`. Every claim below comes from a
page or source file fetched on 2026-10-18, and the URL is given for each. Only
public primary sources were used: official documentation, the provider's own
open-source repositories (actual code files, not search-result summaries), and
official blog posts. Forum posts, third-party address labels, and "this address
belongs to X" claims were excluded. No key was scraped, guessed, or derived:
every key in the registry is one the provider itself published, in a doc, a repo
fixture, or a network-parameter constant, and each is labeled with what it
actually evidences.

Two limitations of the method, stated up front:

- An open-source library proves what that library CAN build. It does not prove
  what the hosted product configures in every case. Where the product and the
  open-source code are the same codebase (Green/gdk, Liana, Specter, Caravan)
  the evidence is strong. Where the product is closed (Casa, AnchorWatch,
  Onramp, BitGo's production service) the code evidence is partial and the
  registry says so.
- Absence of published structure is itself recorded as a finding. Several
  providers publish nothing structural at all.

## Summary: what is publicly knowable per provider

| Provider | Threshold/n | Sorted (BIP67) | Output type | Timelocks | Exact template derivable | Key staticness | Keys/txids published |
|---|---|---|---|---|---|---|---|
| BitGo | 2-of-3 | No (positional user/backup/BitGo) | P2SH, P2SH-P2WSH, P2WSH (default), P2TR (deprecated), P2TR-MuSig2 | None | Yes (open-source SDK) | Per-wallet | 2 API-verification xpubs, doc example xpubs; no wallet keys |
| Unchained | 2-of-3 (product) | Yes | P2SH, P2SH-P2WSH, P2WSH | None | Yes (open-source library) | Per-customer | Demo fixture xpubs (2-of-2 test wallets); no wallet keys |
| Casa | 2-of-3, 3-of-5 | Unknown | P2SH-P2WSH (via recovery guides) | None published | No (app closed source) | Unknown (per-customer implied, unstated) | None |
| AnchorWatch | 2-of-3 | Unknown | P2WSH, explicitly not taproot | CSV, block values unpublished (day 335/380) | No (no public code) | Unknown | None |
| Onramp | 2-of-3 | Unknown | Not published | Not published | No | Unknown | None |
| Blockstream Green | 2-of-2, 2-of-3 | No (flags = 0) | P2SH (v0), P2SH-P2WSH (current) | CSV buckets 25920 / 51840 / 65535 | Yes (open-source SDK + wally) | v0 provider-static; current per-account | Mainnet v0 service pubkey published in source |
| Nunchuk | 2-of-3 default, m-of-n generally | Caller-chosen, not attributable | P2WSH default; P2SH, P2SH-P2WSH, taproot, miniscript selectable | OLDER/AFTER, values server-side, unpublished | Partially (descriptor code) | Unknown (platform key per-group, replaceable) | Doc example xpub only |
| CoinCover | Not published | | | | No | Unknown | None |
| CoinCorner | Not published | | | | No | Unknown | None |

## BitGo

Documented wallet model (https://developers.bitgo.com/docs/wallet-types):
"BitGo offers the following on-chain wallet types that utilize 2-of-3 keys for
transaction signing", with three independent keys per wallet: "User key",
"Backup key", "BitGo key".

Address types (https://developers.bitgo.com/docs/utxo-address-types): `p2sh`
(chain 0), `p2shP2wsh` (chain 10), `p2wsh` (chain 20), `p2trMusig2` (chain 40).
"The default address type for bitcoin wallets at BitGo is `p2wsh` (Native
Segwit)." "The address type `p2tr` with chain code `30` is now deprecated." The
p2trMusig2 type "has enhanced privacy due to its transactions appearing as
single-key and single-signature on chain". This last point matters for the
study: MuSig2 key-path spends must never be attributed from witness shape, and
BitGo itself advertises that property.

Script construction, from the open-source SDK
(https://github.com/BitGo/BitGoJS/blob/master/modules/utxo-lib/src/bitgo/outputScripts.ts):
`scriptTypes2Of3 = ['p2sh', 'p2shP2wsh', 'p2wsh', 'p2tr', 'p2trMusig2']`, and
`createOutputScript2of3` builds `bitcoinjs.payments.p2ms({ m: 2, pubkeys })`.
No sorting step exists between key derivation and script construction. In
`WalletKeys.ts` (https://github.com/BitGo/BitGoJS/blob/master/modules/utxo-lib/src/bitgo/wallet/WalletKeys.ts)
the key triple is positional: `get user() { return this.triple[0]; }`,
`get backup() { return this.triple[1]; }`, `get bitgo() { return this.triple[2]; }`.
So BitGo's on-chain scripts are a fixed-order (unsorted) 2-of-3: user, backup,
BitGo. Corroboration from a fixture the repo itself publishes
(modules/utxo-lib/test/bitgo/fixtures/psbt/inputUpdate.p2shP2wsh.halfSigned.user-bitgo.json):
its witnessScript hex is `OP_2 0336ef... 031214... 03d3ba... OP_3
OP_CHECKMULTISIG`, and BIP67 order of those three keys would start `0312...`,
so the published fixture is not sorted. A further function
(`findSortOrderOfPubKeys` in RootNodes.ts) tries all six permutations against an
observed script, confirming order is wallet-defined, not canonical.

Taproot: for `p2tr` and `p2trMusig2` the code comment states "p2tr/p2trMusig2
addresses use a combination of 2 of 2 multisig scripts distinct from the 2 of 3
multisig used for other script types". Leaves are 2-of-2 pairs; the leaf payment
type `p2tr_ns`
(modules/utxo-lib/src/payments/p2tr_ns.ts) compiles to
"[pubKeys[0:n-1] OP_CHECKSIGVERIFY] pubKeys[n-1] OP_CHECKSIG", i.e. an
all-sign CHECKSIGVERIFY chain, not OP_CHECKMULTISIG. Tree depths: p2tr places
(user,bitgo) at depth 1 and (user,backup), (backup,bitgo) at depth 2;
p2trMusig2 places its two leaves at depth 1 over a MuSig2 key path of
(user,bitgo).

Timelocks: none documented anywhere in the fetched docs or the script-building
code. Recovery is structural, not time-based: an unsigned sweep with user and
backup keys only (wallet recovery wizard README).

Key provenance (https://developers.bitgo.com/docs/wallets-create-multisig-keys):
"BitGo always creates and stores the BitGo key", created in the per-wallet key
creation flow, and wallet code resolves three per-wallet keychain IDs
(modules/abstract-utxo/src/keychains.ts). The docs never state cross-customer
uniqueness in so many words, but the model is a fresh BitGo key per wallet, so
the registry records customer-specific, not provider-static.

Keys BitGo itself publishes: two provider-wide API-verification keys hardcoded
in modules/sdk-core/src/bitgo/environments.ts (serverXpub.prod and hsmXpub.prod,
recorded in the registry). These are API/HSM verification keys, NOT members of
any 2-of-3 wallet script, and the registry labels them as such. Doc example
xpubs from the key-creation guide are also recorded, labeled as examples. No
mainnet txids or addresses published in any fetched doc or fixture.

## Unchained

Product structure: "Every vault is secured by three keys. Two of three are
required to move your bitcoin" (https://www.unchained.com/vaults); "at
Unchained, we only offer 2-of-3 for our bitcoin vaults"
(https://www.unchained.com/blog/bitcoin-multisig-2-of-3-vs-3-of-5). Unchained
holds the third key (collaborative custody).

Script types and sorting, from the open-source stack
(https://raw.githubusercontent.com/unchained-capital/unchained-bitcoin/master/src/multisig.ts):
address types `P2SH`, `P2SH_P2WSH`, `P2WSH` via bitcoinjs `payments.p2ms`; no
P2TR ("P2TR not able to be used anywhere yet" in
src/types/addresses.ts). Sorting: the wallet (braid) flow sorts keys
canonically: `generatePublicKeysAtPath` ends
`return Object.keys(derivePublicKeyObjectsAtPath(braid, path)).sort(); // BIP67`
(https://raw.githubusercontent.com/unchained-capital/unchained-bitcoin/master/src/braid.ts),
and Caravan's one-off address tool warns "WARNING: These public keys are not in
the standard BIP67 order" with a canonical-sort button
(https://raw.githubusercontent.com/unchained-capital/caravan/master/src/components/CreateAddress/AddressGenerator.jsx).
So the wallet flow produces BIP67-sorted multisig; only the raw-API path can
produce unsorted. No timelock, CSV, CLTV, or miniscript construction exists in
either repo (swept).

Key staticness: "Our systems use unique per-customer, multisignature P2SH
addresses. With vaults and multi-institution loans, these addresses are
partially derived using a customer's extended public keys"
(https://www.unchained.com/privacy-security). Customer-specific.

Keys published: the Caravan repo publishes mainnet demo 2-of-2 wallet fixtures
(fingerprints f57ec65d and 00000004, path m/45'/0'/100') at
https://raw.githubusercontent.com/unchained-capital/caravan/master/fixtures/caravan/bitcoin-2-of-2-P2SH_MAINNET.json
and sibling P2SH-P2WSH / P2WSH files. These are published test wallets, not
Unchained-operated keys, and the registry labels them accordingly. The only
on-chain example txids found are testnet examples in the
bitcoin-multisig-older repo. No mainnet txid or deposit address is published by
the company.

## Casa

Structure: "Your 3-key vault requires any 2 of those 3 keys to send a
transaction" (https://support.casa.io/knowledge/getting-started-what-is-multisig);
"A Casa 3-key vault is a standard 2-of-3 multisignature wallet. A 5-key vault is
a standard 3-of-5 multisignature wallet"
(https://support.casa.io/knowledge/what-happens-to-my-funds-if-casa-shuts-down).
Casa holds only the Recovery Key.

Script type: Casa's own sovereign recovery guides instruct customers to build
"p2sh-segwit multisig" from 3 cosigners requiring 2 signatures
(https://support.casa.io/knowledge/sovereign-recovery-for-bitcoin-vaults), and
"Nested Segwit" with 2 of 3 (or 3 of 5) cosigners in Sparrow
(https://support.casa.io/knowledge/sovereign-recovery-with-sparrow-wallet).
This is the strongest published script-type evidence: P2SH-P2WSH wrapped
multisig. Key ordering, exact script bytes, and any conditional structure are
not published, because "The Casa app is not an open-source mobile application"
(https://support.casa.io/knowledge/the-casa-app-and-open-source-software). The
GitHub org holds no wallet-construction code.

Key provenance: Mobile Key and YubiKey seeds are generated on the customer's
device; "Casa generates and holds [the Casa Key] offline" and stores only its
extended public key
(https://blog.casa.io/casa-mobile-key-yubikey-and-casa-key-where-each-one-comes-from/).
Whether the Casa Key is unique per member is never stated; the registry records
unknown rather than inferring.

Absences (explicit findings): no published descriptor example, xpub, pubkey,
address, or txid anywhere in the docs, blog, or repos fetched; no timelock
values (the 2019 Wealth Security Protocol describes an MAST/taproot fallback as
hypothetical and explicitly not implemented); no BIP67 statement.

## AnchorWatch

Architecture, from the FAQ (https://www.anchorwatch.com/faqs): "The 3-Key
Flagship Vault uses a client-controlled 2-of-3 multisig"; the Multi-Institution
Custody vault "distributes keys across AnchorWatch, BitGo, and CoinCorner".
Output type is stated explicitly: "AnchorWatch's Trident Vaults do not currently
use Taproot in their on-chain architecture" and "They are built on native SegWit
Pay-to-Witness-Script-Hash (P2WSH) outputs with miniscript-defined multisig
policies". Timelocks: "A time-based recovery path, built using opcodes such as
OP_CSV, becomes valid after a defined delay", and "After the insurance term
ends, an additional path activates that returns sovereign custody to the
client."

Layer values come only from the Flagship blog post
(https://www.anchorwatch.com/blog/the-flagship-single-key-vault-self-custody-reinforced):
"Layer 2 is the Recovery / Inheritance Layer, available from day 335"
(AnchorWatch and CoinCorner keysets), "Layer 3 is the Sovereign Recovery layer,
available from day 380" (client key alone); the uninsured variant swaps the two
layers. These are calendar days, not block counts: the CSV block values are not
published, and the registry records `value: null` rather than a converted
number. The company states customers receive the per-vault "Recovery Script"
and can compare it against "the descriptor and miniscript policy", but publishes
no example of either.

Absences (explicit findings): the GitHub organization has no public
repositories (https://github.com/anchorwatch); no descriptors, miniscript
fragments, key ordering, xpubs, addresses, or txids published anywhere fetched;
the provider-static versus per-customer question for the institutional keyset is
not answerable from public materials. The registry row for AnchorWatch is
therefore the weakest of the seven providers: threshold and output type are
documented, everything else is null.

## Onramp

Quorum, from the product pages: "three independent institutions form a 2-of-3
multisignature quorum", "Onramp operates the model with Onramp, BitGo Trust,
and CoinCover for individual and IRA accounts" and "with Onramp, Tetra Trust,
and CoinCover for business accounts"
(https://onrampbitcoin.com/products/multi-institution-custody); "Onramp and
CoinCover are part of every vault" and "The bitcoin network enforces that limit
through the multisignature script itself, not a policy or a contractual
promise" (https://onrampbitcoin.com/knowledge-center/multi-institution-bitcoin-custody-who-holds-the-keys).
The same pages describe AnchorWatch's MIC offering (AnchorWatch, BitGo,
CoinCorner as keyholders), corroborated by AnchorWatch's own site.

Absences (explicit findings): no output type, no BIP67 statement, no timelock,
no address-type statement, no xpub, no vault address, no txid published in any
fetched page (including the proof-of-reserves explainer, which describes
dedicated on-chain addresses without publishing any). Whether institutional
keys are per-vault or provider-static is not stated. The 2-of-3 fact is real
but a bare 2-of-3 shape is the most common multisig on mainnet, so this row
carries little discriminating power without on-chain corroboration.

## Blockstream Green

Green is the strongest case: the product's script construction is open source
(gdk) and its dependency (libwally-core) documents the exact script bytes.

Plain multisig accounts:
- 2-of-2 or 2-of-3 (subaccount types "2of2", "2of2_no_recovery" (Liquid only),
  "2of3" per https://github.com/Blockstream/gdk/blob/master/include/gdk.h),
  server key FIRST in the script, user key second, backup key third
  (src/transaction_utils.cpp, `output_script`).
- Keys are NOT sorted: src/ga_wally.cpp passes `const uint32_t flags = 0;` to
  `wally_scriptpubkey_multisig_from_bytes` (no WALLY_SCRIPT_MULTISIG_SORTED).
- Output type: `p2wsh` and `csv` multisig addresses are P2SH-nested (base58
  `3...`), not bech32: "return base58_address(net_params.btc_p2sh_version(),
  witness_program)" in src/transaction_utils.cpp, matching the published doc
  example get_receive_address_multisig.json (a `csv`-type `2N...` testnet
  address). Legacy `p2sh` accounts reveal the bare multisig as redeemScript.

CSV recovery accounts (the distinctive shape): the `csv` address type calls
`wally_scriptpubkey_csv_2of2_then_1_from_bytes`, whose optimized variant (used
on Bitcoin mainnet; Liquid uses the old layout) is documented verbatim in
https://raw.githubusercontent.com/elementsproject/libwally-core/master/src/script.c:

```
<recovery_pubkey> OP_CHECKSIGVERIFY
<main_pubkey> OP_CHECKSIG OP_IFDUP OP_NOTIF
<CSV_BLOCK> OP_CHECKSEQUENCEVERIFY
OP_ENDIF
```

with `csv_blocks` bounded to 17..65535. The block values are Green's mainnet
buckets, published in https://github.com/Blockstream/gdk/blob/master/src/network_parameters.cpp:
`{ "csv_buckets", std::vector<uint32_t>{ 25920, 51840, 65535 } }`, chosen per
account via `GA_set_csvtime`. A "Green-style" witness script with CSV value
51840 and a first-slot server key is about as provider-distinctive as public
sources allow.

Key staticness, split by account version (this nuance is load-bearing):
- Legacy v0 addresses: the service key is a network-level constant,
  "not derived from the user's GA path" (src/transaction_utils.cpp), published
  in the same file as `service_pubkey`
  0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f and
  `service_chain_code` e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d.
  This is a provider-static mainnet pubkey the provider itself published: any
  on-chain script containing it is Green's v0 service key by the provider's own
  definition. It is the only key in this registry with that property.
- Current accounts: server keys derive from the provider master key at
  m/1/gait_path/pointer with a per-user gait path
  (https://github.com/Blockstream/gdk/blob/master/src/xpub_hdkey.hpp), so the
  key material is per-account even though its script position (first slot) is
  constant.

Taproot: exists only as a singlesig subaccount type in the current API
(p2tr for single-sig accounts); no taproot multisig. No mainnet example
addresses or txids are published in the gdk docs (testnet examples only).

## Nunchuk

Wallet model: collaborative wallet configuration is "stored in BSMS format
(built on top of output descriptors)" with `"m": 2, "n": 3, "address_type":
"NATIVE_SEGWIT"` (LEGACY and NESTED_SEGWIT selectable)
(https://github.com/nunchuk-io/docs/blob/main/e2ee-multisig.md). The platform
(Nunchuk server) signer occupies the LAST key slot:
`const int platform_index = group.get_n() - 1;` in MarkPlatformSigners
(https://github.com/nunchuk-io/libnunchuk/blob/main/src/nunchukgroupwallet.cpp).
Inheritance examples put "Key D: Nunchuk Platform Key" in a 2-of-4
(https://github.com/nunchuk-io/docs/blob/main/off-chain_inheritance.md).

Descriptor code
(https://github.com/nunchuk-io/libnunchuk/blob/main/src/descriptor.cpp):
`desc << (sorted ? "(sortedmulti(" : "(multi(") << m;` for segwit, sorted chosen
by the caller, so sortedness is not attributable from public sources; taproot
supports `multi_a`/`sortedmulti_a`, MuSig2 key paths `tr(musig(...))`, and a
DISABLE_KEY_PATH template with an unspendable internal key; miniscript wallets
wrap `wsh(...)` or `tr(keypath, miniscript)` with OLDER (CSV) and AFTER (CLTV)
nodes available (include/nunchuk.h ScriptNode types).

Timelock values and inheritance miniscript templates are fetched from the
Nunchuk server at runtime (`config["miniscriptTemplate"]` in
src/groupservice.cpp) and are not published in any open-source repo: an
explicit absence. No static server xpub exists anywhere in libnunchuk or
nunchuk-desktop (the platform key is fetched per group and replaceable via
CreateReplaceGroup), so key staticness is recorded unknown rather than inferred.
The only published key is a documentation-example BIP-129 signer xpub in the
e2ee doc, recorded as such. Note: docs.nunchuk.io was unreachable (DNS) from
the research environment, so the docs site itself is not cited; repo sources
carry the same claims.

## Institutional co-signers: CoinCover and CoinCorner

- CoinCover: documented as a keyholder only by counterparties. Onramp: "Onramp
  and CoinCover are part of every vault"
  (https://onrampbitcoin.com/knowledge-center/multi-institution-bitcoin-custody-who-holds-the-keys).
  CoinCover's own site lists Onramp and BitGo in its partner directory but
  describes no co-signing role and publishes no script structure
  (https://www.coincover.com/partners/partner-directory).
- CoinCorner: its own Vault page says "keys distributed across multiple
  jurisdictions and held by independent entities - CoinCorner and AnchorWatch"
  (https://www.coincorner.com/vault), with no threshold, address type, or script
  detail. AnchorWatch's FAQ names CoinCorner as the third MIC keyholder.
- Neither publishes any script shape, key, address, or txid. Registry rows for
  both have empty expected_structures by design: their presence matters to the
  study only as candidate shared keys inside Onramp/AnchorWatch quorums, which
  no public source can yet confirm.

## Control groups

These rows exist so the engine can measure false positives; each is fully
derivable from a public primary source.

- Lightning channel funding (BOLT #3,
  https://github.com/lightning/bolts/blob/master/03-transactions.md): "The
  funding output script is a P2WSH to: 2 <pubkey1> <pubkey2> 2
  OP_CHECKMULTISIG", where pubkey1 is "the lexicographically lesser of the two
  funding_pubkey". So: P2WSH 2-of-2, canonically ordered keys, no timelock on
  the funding output (CSV lives on the singlesig to_local/to_remote outputs,
  which are NOT multisig and must not be counted as 2-of-2s). Note the collision
  by design: this template's L3 equals Green's plain 2of2 template; form and
  sortedness and corroborating evidence must separate them.
- Liana (https://github.com/wizardsardine/liana): miniscript inheritance wallet.
  No sortedmulti anywhere at HEAD (the code hits
  `unreachable!("None of our descriptors is a sorted multi")`), keys unsorted.
  Default GUI: taproot on (`use_taproot: true`), multisig template "primary
  2-of-2, recovery 2-of-3", default recovery sequence 52596 blocks ("displays
  1y"). Taproot leaves compile from multi_a to CHECKSIGVERIFY chains ending in
  CHECKSIG plus a NUMEQUAL/NUMEQUALVERIFY threshold check, recovery gated by
  OP_CHECKSEQUENCEVERIFY. P2WSH fallback uses multi() with an older() recovery
  branch. Round-trip test descriptors in the repo evidence the shapes.
- Specter DIY
  (https://github.com/cryptoadvance/specter-desktop/blob/master/src/cryptoadvance/specter/wallet/wallet.py):
  `desc = f"sortedmulti({sigs_required},{desc_keys})"`, wrapped `wsh` (default)
  or `sh-wsh`; threshold user-chosen with no code default; no taproot for
  multisig. This is the canonical DIY BIP67 m-of-n.
- Generic BIP67 2-of-3
  (https://github.com/bips/blob/master/bip-0067.mediawiki): compressed keys
  "Sort them lexicographically according to their binary representation", so a
  key set has a canonical address. The BIP text covers P2SH; P2WSH sorted
  multisig is the ecosystem extension (evidenced by the Specter and Caravan
  code above). 2-of-3 sorted is arguably the single most common multisig shape
  on mainnet, which is exactly why it anchors the false-positive baseline.

## Providers with insufficient public evidence for ANY structural expectation

Honest list. These cannot be attributed by template from public sources alone:

- Onramp: threshold and quorum membership only; no output type, no ordering, no
  timelock, no keys.
- CoinCover: nothing structural at all.
- CoinCorner: nothing structural at all.
- Casa: close second; script type and thresholds are documented, but ordering,
  exact bytes, and keys are not, and the app is closed source.

Providers where public evidence IS sufficient for at least one structural
expectation: BitGo (unsorted positional 2-of-3, five forms), Unchained (sorted
2-of-3, three forms), Blockstream Green (unsorted server-first 2-of-2/2-of-3,
CSV buckets, one provider-static mainnet pubkey), Nunchuk (default-2-of-3
P2WSH with platform key in the last slot), AnchorWatch (P2WSH 2-of-3 with CSV
recovery, values unpublished).
