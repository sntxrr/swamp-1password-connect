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

> **Pass `connectToken` as a reference, never as a literal.** `swamp vault
> create --config` persists the config verbatim into `vaults/<uuid>.yaml`, and
> `.meta({ sensitive: true })` governs **logging**, not what is written to disk.
> A token supplied literally therefore lands in a plaintext file in your repo —
> and, if that repo is public, one `git add -A` from being published.
>
> ```bash
> # Wrong — writes a live JWT into vaults/<uuid>.yaml
> swamp vault create @sntxrr/1password-connect prod \
>   --config '{"connectHost":"https://connect.example.com","connectToken":"eyJhbGciOi...","vaultId":"homelab"}'
>
> # Right — the file stores the reference; the value resolves at run time
> export OP_CONNECT_TOKEN="$(op read 'op://Private/<item-uuid>/token.jwt')"
> swamp vault create @sntxrr/1password-connect prod \
>   --config '{"connectHost":"https://connect.example.com","connectToken":"${{ env.OP_CONNECT_TOKEN }}","vaultId":"homelab"}'
> ```
>
> This bites specifically because the token *is* the vault: it is the one
> credential that cannot be wired with `${{ vault.get(...) }}`, so there is no
> vault indirection to hide behind. Check what actually landed with
> `grep connectToken vaults/**/*.yaml`, and consider adding `vaults/` to
> `.gitignore` outright.

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
