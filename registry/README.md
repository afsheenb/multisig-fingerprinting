# registry/

`providers.json` is the machine-readable attribution registry: script
structures that commercial Bitcoin multisig providers and control-group wallet
software are publicly known to produce, each with the URL that evidences it.
The human-readable version with full quotes is `docs/provider_research.md`
in the repository root.

Schema (top level): `version`, `note`, `conventions`, and `providers`, an array
of rows with:

- `id`, `name`, `control_group` (true for false-positive baselines),
- `sources`: array of `{url, what, retrieved}`,
- `expected_structures`: array of `{form, script_class, threshold, n_keys,
  keys_sorted, timelocks, template_l3, structure_notes, evidence,
  key_staticness}`. Field values mirror the corpus columns in `msfp/db.py`
  (`threshold`, `n_keys`, `keys_sorted`, `script_class`, `template_l3`) so the
  attribution engine can join rows against `revealed_scripts` directly.
  `template_l3` is the exact string `msfp/scripts.py` `build_templates`
  produces, or null when it is not derivable from a public primary source.
  `form` is null when the provider publishes no output type.
- `known_keys`, `known_txids`: only keys and transaction ids the provider
  itself published in docs, repos, or fixtures. Nothing is scraped, guessed,
  or derived. A documentation example or API-verification key is labeled as
  such and is not evidence that an on-chain script contains it.

## Grading rule

A registry row alone grades nothing below D. Template shape is a hypothesis
generator: a row match moves an on-chain script to "candidate" and nothing
more. Attribution requires corroboration outside the template, in this order
of strength: a provider-published static key appearing in the script (strongest,
currently only Green's v0 service pubkey), a published address or txid set, a
distinctive provider-documented timelock value plus form, then bare template
and threshold shape (weakest, and the control groups exist to quantify exactly
how weak that is). The interpretation rules in the repository README bind here:
a shared script template never implies a shared owner, and no provider
attribution without independent evidence.
