# swamp-1password-connect

A [swamp](https://swamp-club.com) vault backend that reads and writes 1Password
secrets over the **1Password Connect HTTP API** — no `op` CLI, no binary, no
desktop session.

## Why this exists

The existing 1Password vault backends shell out to the `op` CLI. That works at a
terminal, but the CLI needs a binary on `PATH` and usually a desktop session for
its integration, so it breaks in exactly the places automation lives: cron jobs,
containers, and `swamp serve`.

1Password Connect is plain HTTP with a bearer token. A native client needs no
binary at all, so a swamp repo can source its secrets unattended.

## Configuration

```yaml
connectHost: https://connect.example.com
connectToken: <token>        # sensitive — a Connect JWT
vaultId: <vault UUID or name>
```

Connect cannot be granted access to the built-in Private, Personal, Employee, or
default Shared vaults — items must live in a custom vault.

> **The `connectToken` is stored on disk in plaintext, and there is no way
> around it.** `swamp vault create --config` persists the config verbatim into
> `vaults/<uuid>.yaml`, and `.meta({ sensitive: true })` governs **logging**, not
> what is written to disk.
>
> A swamp expression does **not** help here: vault configuration is not
> expression-evaluated, because the vault subsystem is what *resolves*
> expressions in the first place. Writing `${{ env.OP_CONNECT_TOKEN }}` into the
> config stores that string literally and Connect then rejects it with a 401.
> Use shell substitution so the real value is written:
>
> ```bash
> export OP_CONNECT_TOKEN="$(op read 'op://Private/<item-uuid>/token.jwt')"
> swamp vault create @sntxrr/1password-connect prod --config "$(python3 -c '
> import json, os
> print(json.dumps({
>     "connectHost": "https://connect.example.com",
>     "connectToken": os.environ["OP_CONNECT_TOKEN"],
>     "vaultId": "homelab",
> }))')"
> ```
>
> **So treat `vaults/` as secret material.** Add it to `.gitignore` — especially
> in a public repository, where it is otherwise one `git add -A` from publishing
> a live credential. This token *is* the vault: it is the one credential that
> cannot be wired through `${{ vault.get(...) }}`, so there is no indirection to
> hide behind. Verify what landed with `grep connectToken vaults/**/*.yaml`.

## Development

```bash
DENO=~/.swamp/deno/deno
DIR=extensions/vaults/onepassword_connect
$DENO check "$DIR/mod.ts"
$DENO test  "$DIR/mod_test.ts"
swamp vault status --json
```

## License

MIT
