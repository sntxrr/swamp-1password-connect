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
