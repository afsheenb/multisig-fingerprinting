# Provider artifact hunt (public sources only)

Companion to `docs/provider_research.md` (structures) and `registry/providers.json`
(machine rows). This file catalogs every provider-published artifact found in the
wild on 2026-10-18, the immediate corpus cross-match result for each, and the
places searched where nothing was found (absence is a finding here, since the
attribution engine grades almost everything D/E for want of anchorable artifacts).

Method and rules, restated from the hunt brief:

- Public, openly accessible sources only: official docs, provider blogs, provider
  GitHub repos (code, test fixtures, READMEs), provider sitemaps and help-center
  pages. No authenticated, paywalled, or private material was opened, and no
  private individual was scraped. No key was guessed or derived: every value below
  is recorded verbatim as found.
- Corpus cross-matching was immediate and read-only against `data/corpus.sqlite3`
  (615,233 txs, 76,435 revealed scripts, 151,465 script keys).
- Matching limitation: an xpub (78 bytes, version 0x0488B21E) can never equal a
  script pubkey, so xpub artifacts cannot match `script_keys.pubkey_hex` directly.
  `msfp/attribute.py` xpub_to_pubkey only extracts the xpub's own 33-byte key,
  which by construction never appears in a descendant script. Full BIP32
  derivation sweeps were out of scope for this pass, so every xpub artifact below
  has corpus match 0 by construction and the meaningful chain-level test is a
  future derivation sweep, not this table.
- GitHub code search was unavailable (unauthenticated code search is closed, and
  the grep.app mirror was bot-blocked), so the cross-cutting BSMS/descriptor sweep
  could not be done by query. It was done by cloning the provider repos directly
  and grepping. Web search results were unreliable in this environment: two
  search-result summaries looked substantive but could not be verified against a
  fetchable page, and are recorded below only as unverified leads.

## Corpus match summary

| Provider | New artifacts | Corpus matches |
|---|---|---|
| BitGo | 7 fixture/descriptor xpubs, 1 attestation xpub, 8 doc-example txids, 1 doc-example address | 0 txs, 0 keys |
| Unchained | 4 new mainnet fixture xpubs (2 fixture wallets) | 0 (xpubs, no direct match possible) |
| Nunchuk | BSMS 1.0 example (testnet), worked recovery tx (testnet), 2 tpubs, 2 witness pubkeys, 1 txid | 0 txs, 0 keys |
| Casa | none verified | n/a |
| AnchorWatch, Onramp, CoinCover, CoinCorner, Tetra Trust | none | n/a |

Zero matches everywhere is the expected outcome for fixture and example keys, and
it is still worth recording: it bounds the corpus-side cost of adding these
artifacts to the registry at exactly zero false positives.

## BitGo

Found (all in the provider's own open-source SDK repos and developer docs):

1. Descriptor-level confirmation of unsorted ordering.
   `modules/abstract-utxo/src/descriptor/builder/builder.ts` builds
   `wsh(multi(2,...))` / `wsh(multi(2,2,...))` with keys in builder order and no
   sort step, plus a `wsh(and_v(r:after(locktime),multi(2,3,...)))` CLTV-drop
   variant used for staking (not for wallet outputs).
   https://github.com/BitGo/BitGoJS/blob/master/modules/abstract-utxo/src/descriptor/builder/builder.ts
   Recorded as a source row on the p2wsh expected_structure; no new structure.
2. Offline-vault recovery fixture with the full key triple and descriptors.
   `Wsh2Of3.buildAdmin.custodial.json` publishes user
   `xpub6CncomMyftm44Wo7zJNgmuQcT153FeE3eb2bDPrWMaStw1eCoheYxCdLszWMqYUWU7HVB57s6mD42HrxqqrETvVu6EcjhbhsQyRwrcyq9ph`,
   backup
   `xpub6C3a1dkbEx4NReyHcdckxRDwedQmKH1EnnUf9xetKpBKaAo2qVckgBAaQfi6FdkQ7wX5YmmwakHsf4RWKFrUm3AGtD1WhkAR7nApvwkABC8`,
   bitgo
   `xpub661MyMwAqRbcFzLg5VNruBcXR52hePxoeszcGETvb5ksucEGKArew5k4mhfTkkPt7NfJ1RCGnGpm7LvNtakVGfg9kBiVi4Ybc43Yv7Uthtc`,
   response descriptors `wsh(multi(2,<user>/0/*,<backup>/0/*,<bitgo>/0/*))`, and a
   computed example address `bc1q96awm56777g6enlzp6qskc2r6hjxvv5ay0d4vrf356nl0255s3xq94kt80`.
   The fixture is synthetic (its input txids are 0x01 patterns), so the address is
   a derivation artifact, not an observed output. The fixture also contains
   throwaway test xprvs; per the hunt rules they are not reproduced here.
   https://github.com/BitGo/BitGoJS/blob/master/modules/abstract-utxo/test/unit/offlineVault/fixtures/Wsh2Of3.buildAdmin.custodial.json
   Corpus: the three xpubs are extended keys, no direct match possible (0).
3. Descriptor test fixture master keys (generic `xpub661MyMw...` BIP32 root keys
   used in `DefaultWsh2Of3.json` and sibling fixtures as the three slots of
   `wsh(multi(2,...))` test descriptors):
   `xpub661MyMwAqRbcGZfgedgcQiBJpkHoZ37k6uotUVLoC6Px4Y46Yrdmy1CUogcJMoAsosY381gPjhGe9jFx1uYAcxy2gTHh9YFP32tUWycqHnV`,
   `xpub661MyMwAqRbcF8FoYWukS8eTn2gVEojzwf5DYETpB8uqC8t5sqDCEFnuJ39DaPjLRerBDK9QqSMvSYpT4WSugCVbUK5HEevSKAu1wUkVWsS`,
   `xpub661MyMwAqRbcFdScyinA4JpCViqkKsd37MQ6fwuZQQ4shdaGRRX9a8bWvR9QC1AFqKongweJJfyrm7uCoWmCw7UixwGZkZnCT2mchFr7cQb`.
   https://github.com/BitGo/BitGoJS/blob/master/modules/abstract-utxo/test/unit/descriptor/createWallet/fixtures/DefaultWsh2Of3.json
   Corpus: 0 (master-key pubkeys, cannot appear in scripts by construction).
4. PayGo attestation xpub, provider-wide:
   `xpub6BKRgmCPX5oQiJgJ6Vq6BF8tDvZhwQki5dVVQohckK2ZJXtxj8K6M9pavLwt9piW33hZz17SWmG8QWsjJ1tHdde2Fs5UA3DFbApCtbdaGKn`
   (`paygoAddressAttestationPubkey` in `modules/statics/src/networks.ts`, returned
   by `getPayGoVerificationPubkey.ts`). A verification key, not a wallet script key.
   https://github.com/BitGo/BitGoJS/blob/master/modules/statics/src/networks.ts
   Corpus: 0 by construction (xpub).
5. Eight doc-example txids, recorded with low confidence labels. The withdraw
   guide pages (self-custody-simple, custody, manual, offline-vault) embed sample
   API responses with values labeled `validTransactionHash`:
   `4929b91960acdf2d18076ac6151d0aff96b4f4834f9f78eaf40e78ce05f5c0a4`,
   `e7648c85edac7f9870e511b4ef95b62b1878556791bd52ac715cb2cd4b466e6f`,
   `8747673834d6c71560a2816963585718567419020dc58151d2f7e1ed8c57de14`,
   `ff40ccd5c8ba75ffdce27d8584b6e8ee625cb3f71f7cbb6d072a445a97c2c8c3`,
   `d5621704d7dd06d55c6016709e75a1787fb661d565290611e3eff914f03a4d0e`,
   `c68916ddc1672ec62c474ef0839ec479ad9b2dabc2249177ce6be6247f81dfe7`,
   `5ea8d2b93997ed9fa3597a2f3113817c8216f573a0278c2533bb5db50fdb0dff`.
   The full raw transaction hex shown beside these values is present in the pages,
   and recomputing its txid (witness-stripped) never matches the accompanying
   `validTransactionHash`, so these look synthetic. The eighth txid,
   `b0b7e5c2fbbbeb42478f91e1c14b300624a9419631e70dd1564084fb28a55155`, is the
   parseTx example in the utxo-bin README, an arbitrary example transaction.
   https://developers.bitgo.com/docs/withdraw-wallet-type-self-custody-multisig-simple
   https://developers.bitgo.com/docs/withdraw-wallet-type-custody-multisig
   https://developers.bitgo.com/docs/withdraw-wallet-type-self-custody-multisig-manual
   https://developers.bitgo.com/docs/withdraw-wallet-type-bitgo-offline-vault-multisig
   https://github.com/BitGo/BitGoJS/blob/master/modules/utxo-bin/README.md
   Corpus: all 8 absent from `txs`.
6. Doc-example address for the mempool-side agent:
   `3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC` (parseAddress example, utxo-bin README).
   This address is widely reused in bitcoinjs documentation; expect it to be an
   ordinary P2SH, not a BitGo wallet. Corpus: addresses are out of scope for this
   pass (mempool agent owns chain lookups).

Also examined, nothing found: `modules/utxo-lib` and `modules/abstract-utxo` test
fixtures carry only dummy hashes (0x01/0xff patterns); the `cryptographic-keys`
and `wallets-recover` doc pages carry no example keys, addresses, or txids; the
`wallet-recovery-wizard` repo carries four generic root-level `xpub661MyMw...`
test keys and no txids; no mainnet txid or wallet address is published in any
fetched doc.

## Unchained

Found: the Caravan fixtures directory holds three mainnet 2-of-2 demo wallets,
not one. Two new fixture wallets beyond the already-recorded P2SH fixture:

- P2SH-P2WSH mainnet fixture, path `m/48'/0'/100'/1'`, fingerprints `00000005`
  and `f57ec65d`:
  `xpub6EwJjKaiocGvo9f7XSGXGwzo1GLB1URxSZ5Ccp1wqdxNkhrSoqNQkC2CeMsU675urdmFJLHSX62xz56HGcnn6u21wRy6uipovmzaE65PfBp`,
  `xpub6DcqYQxnbefzEBJF6osEuT5yXoHVZu1YCCsS5YkATvqD2h7tdMBgdBrUXk26FrJwawDGX6fHKPvhhZxKc5b8dPAPb8uANDhsjAPMJqTFDjH`
  https://raw.githubusercontent.com/unchained-capital/caravan/master/fixtures/caravan/bitcoin-2-of-2-P2SH-P2WSH_MAINNET.json
- P2WSH mainnet fixture, path `m/48'/0'/100'/2'`, fingerprints `00000006` and
  `f57ec65d`:
  `xpub6EwJjKaiocGvqSuM2jRZSuQ9HEddiFUFu9RdjE47zG7kXVNDQpJ3GyvskwYiLmvU4SBTNZyv8UH53QcmFEE23YwozE61V3dwzZJEFQr6H2b`,
  `xpub6DcqYQxnbefzFkaRBK63FSE2GzNuNnNhFGw1xV9RioVG7av6r3JDf1aELqBSq5gt5487CtNxvVtaiJjQU2HQWzgG5NzLyTPbYav6otW8qEc`
  https://raw.githubusercontent.com/unchained-capital/caravan/master/fixtures/caravan/bitcoin-2-of-2-P2WSH_MAINNET.json

Notable: the fingerprint `f57ec65d` root recurs across all three mainnet fixtures
at different derivation paths, so the demo material is one published test seed
reused, not provider wallet keys. Corpus: 0 (xpubs, no direct match possible).

Also examined, nothing found: the rest of the Caravan repo (testnet `tpub`
fixtures only), the `unchained-bitcoin` repo (no xpub constants in code or JSON),
and blog posts on quorum options, address types, derivation paths, batch
spending, and the multisig security ceiling, whose only 64-hex strings are CSS/
analytics identifiers and whose addresses are famous historical examples
(genesis coinbase, first P2WSH spend from block 481,824), not Unchained wallets.

## Nunchuk

Found, all testnet, in the provider's own knowledge-base repo:

1. A provider-published BSMS 1.0 example, the first BSMS file found from any
   provider in this study. The descriptor template on its second line is:

   ```
   wsh(sortedmulti(1,[6b7c8e84/48'/1'/1']tpubDDnhmLtGvcXQwi4gGhKKTxQeXVXPjivpfWT9aiZ3VENrRTrzMLj4xymfisG18eVshwovyD9Z1zeqBoB8n7VhXaJkHj6yw3ib8BjAaMViDwU/**,[721143dc/48'/1'/2']tpubDD2nPnKDRg6NwikecMFyzPZRSBAKjR2FzcSe46mxWBByShLYwQ19zKpFPL8oMuuwibHXNfuRSknD22xWs7rqf9FShjm8d5SzNNTNpx3Z3kM/**))
   ```

   https://github.com/nunchuk-io/resources/blob/main/content/wallet-recovery/core-recovery/_index.en.md
   Structural value: the provider's own example uses `sortedmulti`, so sorted
   ordering is evidenced for at least one published wallet configuration (the
   open-source descriptor code keeps the flag caller-chosen; the registry row
   keeps `keys_sorted: null` and carries this evidence in its notes). Corpus: 0
   (testnet keys; xpubs, no direct match possible).
2. A complete worked recovery example with raw signed transaction hex and its
   txid `b91276af8b6f5ede632aadfb87bf8a9209a43d0a030396cd0c4629a1ec92b87a`
   (spends input `3fa165538ef2788c6d89c55e2d43a6b336250da5c3e4a6ced20f924fcb1a01bc`).
   The witness script is a 1-of-2 CHECKMULTISIG containing two compressed
   pubkeys verbatim:
   `0295ba49a8e78beac3210989b3a9ed54e7b7c01b867ede611df42a66367625f3a0` and
   `03b1f700197b059c167bdc1b54fd6e354c21aec852a8051468716111ba547d96dd`
   (already in lexicographic order). These two are direct-matchable 33-byte
   keys, so they were queried exactly. Corpus: 0 in `script_keys`, and the txid
   is absent from `txs` (expected: the example is testnet and the corpus is
   mainnet). Recorded in the registry as the first provider-published txid row.
3. The same guide's `tb1q...` recipient addresses are testnet; not carried to the
   mempool agent.

Also examined, nothing found: the collab-wallet and personal-wallet recovery
guides (mainnet instructions, screenshot-only evidence, no keys), the
getting-started BSMS sections (no example files), the `libnunchuk` repo (its
`examples/bsms.cpp` generates fresh random keys, and the only fixed keys are two
testnet `tpub`s in examples), and the `nunchuk-desktop` repo (no xpub constants;
miniscript templates are fetched from the Nunchuk server at runtime and are not
in the client, confirming the earlier absence finding).

## Casa

Nothing verified. The one real lead: a search-result summary of the blog post
"New Feature: Emergency Lock-In TxID" (Jameson Lopp, 2019) quoted a live example
`txid:address` pair, said to be a 3-of-5 emergency lock-in spend created by the
author:

- candidate txid `f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd`
- candidate address `bc1qgnsq6zuzctep7c53vpjye67k3dvc6ps47jmdde`

The post is gone: `https://blog.casa.io/new-feature-emergency-lock-in-txid/`
returns 404, the current blog sitemap (236 posts) does not include it, and the
Wayback Machine availability API has no snapshot at either the blog.casa.io or
blog.keys.casa slug (the Internet Archive itself was partially offline during the
hunt, so a deeper CDX sweep is worth one retry). The quote therefore fails the
"verbatim from a fetchable page" bar and is NOT recorded in the registry; the
candidate txid is absent from the corpus `txs` table. Hand both values to the
mempool-side agent as a lead only: if the txid exists on mainnet and the
address is the multisig-looking one the article describes, it would be Casa's
only published vault-related on-chain artifact and is worth an archiving pass.

Everything else examined, nothing found: the five current blog posts most likely
to carry artifacts (sovereign recovery, recovery key, introduction to multisig,
time-locking challenges, 2024 hardware signing performance) contain no txids,
xpubs, or addresses beyond the historical examples; the GitHub org holds only
Casa Node components, forks, and the Wealth Security Protocol PDF; the help
center (now HubSpot-hosted) exposes no machine-readable example data. Casa
remains the provider whose closed source plus lack of published artifacts makes
template-plus-corroboration attribution impossible from public materials alone.

## AnchorWatch

Nothing found. The full blog index (28 posts) was swept: the only structural
mention in the whole set is the already-recorded flagship post (miniscript,
layered recovery at day 335/380). The inheritance-infrastructure launch post,
the pricing/insurance post, the MIC post, and the CoinCorner partnership post
contain no descriptors, miniscript fragments, xpubs, addresses, or txids. The
GitHub organization still has no public repositories. Their miniscript tooling
("Trident") has no published policy examples anywhere open.

## Onramp

Nothing found, now with wider coverage. The full sitemap was swept: the custody
articles beyond the already-recorded pages (collaborative-vs-multi-institution,
does-MIC-protect-against-6102, custody-for-large-positions, the custody
insurance disclosure under /research, and the Argo product page) contain no
xpubs, addresses, or txids. Onramp publishes the quorum membership (Onramp +
BitGo Trust + CoinCover, or Onramp + Tetra Trust + CoinCover) and nothing else
structural.

## CoinCover, CoinCorner, Tetra Trust

Nothing found. CoinCover's blog index carries nothing on Onramp quorums or any
script structure (its Ledger Recover series covers share distribution for that
product, not multisig scripts, and mentions no Bitcoin multisig keys). Tetra
Trust's site and newsroom have no Onramp mention and no structural content.
CoinCorner's Vault page remains threshold-free. All three remain candidate
shared-key holders inside Onramp/AnchorWatch quorums with zero public key
material to anchor them.

## Cross-cutting

- BSMS files: the Nunchuk recovery-guide example (above) is the only
  provider-published BSMS 1.0 file found. GitHub-wide code search for more was
  not possible without authentication (grep.app bot-blocked, WebSearch
  unreliable); this sweep should be retried from an authenticated environment.
- Output descriptors with provider names nearby: no provider publishes a
  customer-facing descriptor except BitGo (its own SDK fixtures, unsorted
  `multi()`) and Nunchuk (its own BSMS example, `sortedmulti()`), both recorded.
- Known post-hunt gap: provider "known-address" sets (e.g. a company publishing
  its vault deposit addresses for proof of reserves) would be the strongest
  anchorable artifact class and none of the ten providers publishes one.

## Handoff list for the mempool-side agent

Mainnet chain lookups (this agent did not query the chain):

1. BitGo sample `validTransactionHash` values (expect synthetic or unrelated):
   the eight txids listed in the BitGo section.
2. BitGo utxo-bin example address `3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC` (expect
   an ordinary P2SH).
3. Casa lead (unverified quote from a deleted post): txid
   `f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd`, address
   `bc1qgnsq6zuzctep7c53vpjye67k3dvc6ps47jmdde`. Highest-value lookup on the
   list: if real and multisig, it is Casa's only published on-chain artifact.

## Chain lookup results (2026-10-19, mempool.space client)

Every lookup went through `msfp/mempool.py` (1 request/second, 30/minute,
each recorded in `mempool_ledger`, each 200 response permanently cached
under `data/cache_mempool/`). Requests: 8 tx lookups + 1 address lookup
for BitGo, 1 tx lookup + 1 address lookup for Casa. No other network
calls. Nunchuk examples were skipped per the handoff (testnet by
construction).

### 1. BitGo doc txids: 7 synthetic, 1 real-but-unrelated

Seven of the eight doc-example `validTransactionHash` values do NOT
exist on mainnet (mempool.space `GET /tx/{txid}` answered 404 for each;
the 404s are recorded in `mempool_ledger`):

- `4929b91960acdf2d18076ac6151d0aff96b4f4834f9f78eaf40e78ce05f5c0a4`
- `e7648c85edac7f9870e511b4ef95b62b1878556791bd52ac715cb2cd4b466e6f`
- `8747673834d6c71560a2816963585718567419020dc58151d2f7e1ed8c57de14`
- `ff40ccd5c8ba75ffdce27d8584b6e8ee625cb3f71f7cbb6d072a445a97c2c8c3`
- `d5621704d7dd06d55c6016709e75a1787fb661d565290611e3eff914f03a4d0e`
- `c68916ddc1672ec62c474ef0839ec479ad9b2dabc2249177ce6be6247f81dfe7`
- `5ea8d2b93997ed9fa3597a2f3113817c8216f573a0278c2533bb5db50fdb0dff`

This confirms the earlier suspicion for the withdraw-guide samples: the
values labeled `validTransactionHash` are fabricated placeholders, not
observed transactions.

The eighth, `b0b7e5c2fbbbeb42478f91e1c14b300624a9419631e70dd1564084fb28a55155`
(the `parseTx` example in the utxo-bin README), DOES exist: confirmed in
block 793,101 (2023-06-06 10:47:19 UTC). Its structure is an ordinary
one-input batch spend: single P2WPKH input from
`bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h` (8,881,849 sats, witness
stack of one 72-byte DER ECDSA signature plus one 33-byte compressed
pubkey, no script), 78 outputs of mixed type (33 `p2sh`, 34
`v0_p2wpkh`, 3 `v1_p2tr`, 8 `p2pkh`). Nothing about it is BitGo-shaped
(no multisig, no 2-of-3 structure, no provider address pattern); it is
a real unrelated transaction the README used as an arbitrary example.
Verdict: no BitGo doc txid is a BitGo wallet artifact, and none can
anchor anything.

### 2. BitGo doc address: exists, ordinary P2SH, not BitGo's

`3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC` exists and carries a long, active
mainnet history (the address txs page returns its cap of 50 confirmed
transactions, the newest seen mined in block 944,217 in 2026). It is
the widely reused bitcoinjs documentation example address, exactly as
expected; not a BitGo wallet.

### 3. Casa lead: RESOLVED NEGATIVE, with a structural finding

The txid quoted by the search-result summary of the deleted
"Emergency Lock-In TxID" post DOES exist on mainnet, but it is NOT a
Casa artifact, and the quoted address cannot exist at all:

- `f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd`
  is confirmed in block 481,824 (2017-08-24 01:57:37 UTC). Its full
  fetched structure: version 1, locktime 0, size 269, weight 746, fee
  31,240 sats; ONE input, a P2WPKH prevout
  (`00148d7a0a3461e3891723e5fdf8129caa0075060cff`,
  `bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c`, 194,300 sats) spent
  with a single 72-byte DER ECDSA signature plus one compressed pubkey
  (witness stack of 2, no script); THREE outputs: two 81,530-sat
  P2WPKH outputs back to the same address, and a zero-value OP_RETURN
  whose payload decodes verbatim to `#Bitbank Inc. Japan supports
  SegWit!` (script hex
  `6a2342697462616e6b20496e632e204a6170616e20737570706f7274732053656757697421`).
  This is the famous first-ever SegWit spend (block 481,824 is the
  first SegWit block). It contains no multisig, no 3-of-5, nothing
  Casa-shaped, and predates the 2019 post by two years.
- `bc1qgnsq6zuzctep7c53vpjye67k3dvc6ps47jmdde` is syntactically
  INVALID: mempool.space answers HTTP 400 "Invalid Bitcoin address"
  (bech32 checksum failure). No mainnet address with these characters
  exists.

Conclusion: the search-result summary carried at least one fabricated
or corrupted value (the invalid address), and its txid belongs to a
different, famous transaction. The lead is dead on both counts. What
is and is not verified, explicitly: it IS verified that the txid exists
and what its structure is (fetched, cached, ledgered); it is NOT
verified that the deleted post ever contained either value, because the
post was never archived. The archive sweep performed: Wayback
availability API empty for both `blog.casa.io/new-feature-emergency-lock-in-txid/`
and `blog.keys.casa/new-feature-emergency-lock-in-txid/`; CDX exact and
prefix queries return nothing; a whole-domain CDX sweep of `casa.io`
for emergency-lockdown/lock-in URLs surfaces only unrelated pages
(product-update, docs, support); archive.today is unreachable from
this host. Casa therefore keeps zero verified on-chain artifacts and
the row stays "none verified"; no artifact graduated to corpus match or
grade-relevant anchor status from this hunt.
