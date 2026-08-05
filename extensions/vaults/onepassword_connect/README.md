# @sntxrr/1password-connect

A swamp **vault backend** backed by a self-hosted
[1Password Connect](https://developer.1password.com/docs/connect/) server.

Every other 1Password vault backend in the registry shells out to the `op` CLI,
which needs a binary on the host and — in practice — a desktop session or a
service account dance to unlock. That breaks in exactly the places automation
lives: cron jobs, containers, and `swamp serve`. Connect is plain HTTP with a
bearer token, so this extension talks to it directly with Deno's built-in
`fetch`. No binary, no session, no SDK.

Once configured, any model can source secrets with
`${{ vault.get(<vault>, <key>) }}`.

## Installation

```sh
swamp extension pull @sntxrr/1password-connect
```

## Configuration

```yaml
# .swamp.yaml
vault:
  type: "@sntxrr/1password-connect"
  config:
    connectHost: "https://connect.example.com"
    connectToken: "${OP_CONNECT_TOKEN}"
    vaultId: "swamp-secrets"
```

| Key                  | Required | Default                      | Meaning                                                |
| -------------------- | -------- | ---------------------------- | ------------------------------------------------------ |
| `connectHost`        | yes      | —                            | Connect base URL, e.g. `http://192.0.2.10:8080`        |
| `connectToken`       | yes      | —                            | Connect API token (a JWT). Sensitive; never logged.    |
| `vaultId`            | yes      | —                            | Vault ID **or** vault name                             |
| `defaultFieldLabels` | no       | `["password", "credential"]` | Field labels tried when a key names no field           |
| `itemCategory`       | no       | `LOGIN`                      | Category used for items `put` has to create            |
| `timeoutMs`          | no       | `10000`                      | Per-request timeout, so a hung call cannot stall a run |

`vaultId` accepts either form, but **prefer the ID** — Connect's item routes are
ID-native, so a name costs one extra round trip on the first call (the result is
cached for the life of the provider). A 1Password vault ID is 26 lowercase
alphanumeric characters.

The same environment this reads from is what the 1Password Ansible collection
uses, so `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN` can be shared across both.

## Addressing secrets

Keys are `item` or `item/field`:

```sh
# The item's default field: password, then credential, then its lone
# populated field.
swamp vault get "Cloudflare API"

# An explicit field. Spaces are fine on both sides of the slash — keys are
# never split on whitespace.
swamp vault get "backup service/api key"

# Write. Creates the item if it does not exist, updates the field if it does.
swamp vault put "Cloudflare API/api key" "$NEW_TOKEN"

# Item titles in the vault.
swamp vault list
```

Item titles containing `/` work too: the separator is the **last** slash, and if
that split names no item, the whole key is retried as a title.

## How it works

`get` resolves the vault (ID used directly, name resolved through
`GET /v1/vaults?filter=title eq "…"`), finds the item by exact title, then reads
the item _detail_ endpoint — the list endpoint omits every field value.

`put` matters more, because **Connect's item update is a destructive replace**:
whatever field set the request body carries becomes the item's entire field set.
Sending only the field you meant to change silently deletes every other field on
the item. This extension always reads the full item first and writes back every
field, section membership included, with only the target field changed. There is
a unit test asserting exactly that.

Errors are written to be actionable rather than terse. A `401` says the token is
missing, malformed, expired, or from a different Connect server. A `403` or an
empty vault lookup says the token was not granted that vault — and reminds you
that Connect can _never_ read the built-in Private/Personal/Employee vaults or
the default Shared vault, which is the single most common cause of a vault that
"exists" but is invisible.

Secret values and the Connect token never appear in an error message or a log
line.

## Prerequisites

- A reachable 1Password Connect server (`connectHost`).
- A Connect token explicitly granted the target vault.
- The vault must not be a built-in Private/Personal/Employee or default Shared
  vault — Connect cannot see those.

## Development

```sh
~/.swamp/deno/deno check mod.ts
~/.swamp/deno/deno test mod_test.ts
```

The test suite mocks `fetch` end to end; it makes no network calls and needs no
credentials.

## License

MIT — see [LICENSE.md](./LICENSE.md).
