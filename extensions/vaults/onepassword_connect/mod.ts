/**
 * 1Password Connect vault backend for swamp.
 *
 * Registers a swamp vault provider (`@sntxrr/1password-connect`) backed by a
 * self-hosted [1Password Connect](https://developer.1password.com/docs/connect/)
 * server. Once configured, any model can source secrets with
 * `${{ vault.get(<vault>, <key>) }}` expressions.
 *
 * Unlike the `op`-CLI-based vault backends, this one speaks Connect's plain HTTP
 * API with a bearer token and Deno's built-in `fetch`. There is no binary to
 * install and no desktop session to unlock, so it works from cron, from a
 * container, and from `swamp serve`.
 *
 * Secrets are addressed as `item` or `item/field`:
 *
 * - `Cloudflare API` — the item's default field (`password`, then `credential`,
 *   then a lone populated field).
 * - `Cloudflare API/api key` — that exact field label. Item titles and field
 *   labels containing spaces are fully supported; the key is never split on
 *   whitespace.
 *
 * A Connect server can only see vaults its token was granted, and it can never
 * see the built-in Private/Personal/Employee vaults or the default Shared vault.
 *
 * @module
 */
// extensions/vaults/onepassword_connect/mod.ts
import { z } from "npm:zod@4";

/**
 * Configuration schema for the `@sntxrr/1password-connect` vault type, as
 * supplied under `vault.config` in `.swamp.yaml`.
 */
export const ConfigSchema = z.object({
  connectHost: z.string().url().describe(
    "Base URL of the 1Password Connect server, e.g. https://connect.example.com or http://192.0.2.10:8080. No trailing path.",
  ),
  connectToken: z.string().min(1).meta({ sensitive: true }).describe(
    "1Password Connect API token (a JWT) sent as `Authorization: Bearer`. This IS the vault, so it cannot be wired with ${{ vault.get(...) }} — supply it via --config or an env-substituted value. Never logged.",
  ),
  vaultId: z.string().min(1).describe(
    "Vault to read and write. Accepts either a 1Password vault ID (26 lowercase alphanumeric characters) or a vault name, which is resolved to an ID on first use. Prefer the ID: Connect's item routes are ID-native, so a name costs one extra round trip.",
  ),
  defaultFieldLabels: z.array(z.string()).default(["password", "credential"])
    .describe(
      "Field labels tried, in order, when a key names an item but not a field. If none match and the item has exactly one populated field, that field is used.",
    ),
  itemCategory: z.string().default("LOGIN").describe(
    "1Password category used for items `put` has to create. Existing items keep their own category.",
  ),
  timeoutMs: z.number().int().positive().default(10000).describe(
    "Abort any single Connect HTTP call after this long. Guards scheduled runs, where a hung request would otherwise stall the whole execution.",
  ),
});

/** Validated `@sntxrr/1password-connect` configuration. */
export type ConnectVaultConfig = z.infer<typeof ConfigSchema>;

/** A single field on a 1Password item, as Connect represents it. */
export interface ConnectField {
  /** Connect-assigned field identifier, unique within the item. */
  id: string;
  /** Human-visible field label, e.g. `password` or `api key`. */
  label?: string;
  /** Field value. Only ever populated by the item *detail* endpoint. */
  value?: string;
  /** Field type, e.g. `CONCEALED`, `STRING`, `URL`. */
  type?: string;
  /** Well-known role for template categories, e.g. `PASSWORD`, `NOTES`. */
  purpose?: string;
  /** Section the field belongs to, when the item uses sections. */
  section?: { id: string };
}

/** A 1Password item, as returned by Connect's item detail endpoint. */
export interface ConnectItem {
  /** Connect-assigned item identifier. */
  id: string;
  /** Item title — the part of a secret key before the `/`. */
  title: string;
  /** Vault the item lives in. */
  vault: { id: string };
  /** 1Password category, e.g. `LOGIN`, `API_CREDENTIAL`, `SECURE_NOTE`. */
  category: string;
  /** Every field on the item. Values are present only on the detail endpoint. */
  fields?: ConnectField[];
  /** Sections referenced by `field.section.id`. */
  sections?: Array<{ id: string; label?: string }>;
}

/** The provider contract swamp expects back from `createProvider`. */
export interface VaultProvider {
  /** Read a secret value addressed as `item` or `item/field`. */
  get(secretKey: string): Promise<string>;
  /** Create or update the item/field addressed by `secretKey`. */
  put(secretKey: string, secretValue: string): Promise<void>;
  /** List the item titles visible in the configured vault. */
  list(): Promise<string[]>;
  /** Name of this vault instance. */
  getName(): string;
}

/** A secret key split into the item it names and the field it may name. */
export interface ParsedSecretKey {
  /** Item title to resolve. */
  itemTitle: string;
  /** Explicit field label, or `null` when the key named only an item. */
  fieldLabel: string | null;
}

/** 1Password identifiers are 26 lowercase alphanumeric characters. */
const OP_ID_PATTERN = /^[a-z0-9]{26}$/;

/**
 * Split a secret key into an item title and an optional field label.
 *
 * The separator is the **last** `/`, so item titles may themselves contain
 * slashes (`infra/prod db/password` → item `infra/prod db`, field `password`).
 * Whitespace is never a separator: `Connect Token/api key` parses to the item
 * `Connect Token` and the field `api key`, both with their spaces intact. A key
 * with no `/`, a leading `/`, or a trailing `/` is treated as a bare item title.
 */
export function parseSecretKey(secretKey: string): ParsedSecretKey {
  const key = secretKey.trim();
  const idx = key.lastIndexOf("/");
  if (idx <= 0 || idx === key.length - 1) {
    return { itemTitle: key, fieldLabel: null };
  }
  return {
    itemTitle: key.slice(0, idx).trim(),
    fieldLabel: key.slice(idx + 1).trim(),
  };
}

/**
 * Escape a value for interpolation into a Connect SCIM-style
 * `title eq "..."` filter, so titles containing quotes or backslashes cannot
 * break out of the literal.
 */
export function escapeFilterValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/**
 * Choose the field a bare (field-less) key should read.
 *
 * Tries `preferredLabels` in order — case-insensitively, and also matching the
 * template `purpose` so a Login item's password field is found whatever its
 * label reads. Falls back to the item's only populated field. Returns `null`
 * when nothing is unambiguous, which callers turn into an actionable error
 * listing the labels that do exist.
 */
export function pickDefaultField(
  fields: ConnectField[],
  preferredLabels: string[],
): ConnectField | null {
  for (const preferred of preferredLabels) {
    const wanted = preferred.toLowerCase();
    const hit = fields.find((f) =>
      (f.label ?? "").toLowerCase() === wanted ||
      (f.purpose ?? "").toLowerCase() === wanted
    );
    if (hit) return hit;
  }
  const populated = fields.filter((f) => (f.value ?? "") !== "");
  return populated.length === 1 ? populated[0] : null;
}

/** Format the labels an item does have, for "no such field" errors. */
function describeLabels(fields: ConnectField[]): string {
  const labels = fields.map((f) => f.label ?? f.id);
  return labels.length > 0 ? labels.join(", ") : "(none)";
}

/**
 * Create a 1Password Connect–backed vault provider.
 *
 * `name` is the vault instance name from `.swamp.yaml`; `config` is validated
 * against {@linkcode ConfigSchema}. The resolved vault ID is cached for the life
 * of the provider, so a name-configured vault costs one lookup, not one per key.
 */
function createConnectProvider(
  name: string,
  config: Record<string, unknown>,
): VaultProvider {
  const cfg = ConfigSchema.parse(config);
  const base = cfg.connectHost.replace(/\/+$/, "");
  let cachedVaultId: string | null = null;

  /**
   * One authenticated Connect call. Returns parsed JSON, or throws an error
   * that names the failure mode — never the token and never a secret value.
   */
  const request = async <T>(
    method: "GET" | "POST" | "PUT",
    path: string,
    body?: unknown,
  ): Promise<T> => {
    let res: Response;
    try {
      res = await fetch(`${base}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${cfg.connectToken}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(cfg.timeoutMs),
      });
    } catch (cause) {
      const reason = cause instanceof Error && cause.name === "TimeoutError"
        ? `timed out after ${cfg.timeoutMs}ms`
        : String(cause);
      throw new Error(
        `1Password Connect ${method} ${path} failed: ${reason}. Check that ${base} is reachable from this host.`,
      );
    }

    const text = await res.text();
    if (res.status === 401) {
      throw new Error(
        `1Password Connect rejected the credentials (401) on ${method} ${path}. The connectToken for vault "${name}" is missing, malformed, expired, or was issued by a different Connect server than ${base}.`,
      );
    }
    if (res.status === 403) {
      throw new Error(
        `1Password Connect denied access (403) on ${method} ${path}. The token for vault "${name}" was not granted this vault. Re-issue the Connect token with the vault selected — Connect can never read the built-in Private/Personal/Employee or default Shared vaults.`,
      );
    }
    if (!res.ok) {
      throw new Error(
        `1Password Connect ${method} ${path} failed: ${res.status} ${
          text.slice(0, 500)
        }`,
      );
    }
    if (!text) return null as T;
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new Error(
        `1Password Connect ${method} ${path} returned a non-JSON body (${res.status}). Is ${base} really a Connect server?`,
      );
    }
  };

  /** Look a vault up by title, returning its ID or `null` when invisible. */
  const findVaultByName = async (title: string): Promise<string | null> => {
    const filter = encodeURIComponent(`title eq "${escapeFilterValue(title)}"`);
    const vaults = await request<Array<{ id: string; name?: string }>>(
      "GET",
      `/v1/vaults?filter=${filter}`,
    );
    if (!Array.isArray(vaults) || vaults.length === 0) return null;
    return vaults[0].id;
  };

  /**
   * Resolve `cfg.vaultId` — an ID or a name — to a vault ID, once per provider.
   */
  const resolveVaultId = async (): Promise<string> => {
    if (cachedVaultId !== null) return cachedVaultId;

    // An ID-shaped value is used directly; Connect's item routes are ID-native,
    // so this is the cheap path. A 403 here is a real grant problem and is
    // allowed to propagate with its actionable message.
    if (OP_ID_PATTERN.test(cfg.vaultId)) {
      try {
        await request<{ id: string }>(
          "GET",
          `/v1/vaults/${encodeURIComponent(cfg.vaultId)}`,
        );
        cachedVaultId = cfg.vaultId;
        return cachedVaultId;
      } catch (cause) {
        // Only a 404 is ambiguous: a vault could legitimately be *named*
        // something ID-shaped. Anything else (401/403/network) is fatal.
        if (!(cause instanceof Error) || !cause.message.includes(" 404 ")) {
          throw cause;
        }
      }
    }

    const byName = await findVaultByName(cfg.vaultId);
    if (byName === null) {
      throw new Error(
        `Vault "${cfg.vaultId}" was not found on ${base}, or the Connect token has no access to it. Connect only sees vaults explicitly granted to its token, and can never read the built-in Private/Personal/Employee or default Shared vaults.`,
      );
    }
    cachedVaultId = byName;
    return cachedVaultId;
  };

  /** Find an item by exact title within the vault, or `null`. */
  const findItemByTitle = async (
    vaultId: string,
    title: string,
  ): Promise<{ id: string } | null> => {
    const filter = encodeURIComponent(`title eq "${escapeFilterValue(title)}"`);
    const items = await request<Array<{ id: string; title?: string }>>(
      "GET",
      `/v1/vaults/${encodeURIComponent(vaultId)}/items?filter=${filter}`,
    );
    if (!Array.isArray(items) || items.length === 0) return null;
    return { id: items[0].id };
  };

  /**
   * Fetch the **detail** representation of an item.
   *
   * This is load-bearing for `put`: the list endpoint omits every field value,
   * so writing a listed item back would blank the whole item.
   */
  const fetchItem = async (
    vaultId: string,
    itemId: string,
  ): Promise<ConnectItem> =>
    await request<ConnectItem>(
      "GET",
      `/v1/vaults/${encodeURIComponent(vaultId)}/items/${
        encodeURIComponent(itemId)
      }`,
    );

  /**
   * Resolve a key to its item, tolerating item titles that contain `/`.
   *
   * `a/b` is first read as item `a`, field `b`; if no item `a` exists the whole
   * key is retried as an item title.
   */
  const resolveItemForKey = async (
    vaultId: string,
    secretKey: string,
  ): Promise<{ item: ConnectItem; fieldLabel: string | null }> => {
    const parsed = parseSecretKey(secretKey);
    const found = await findItemByTitle(vaultId, parsed.itemTitle);
    if (found !== null) {
      return {
        item: await fetchItem(vaultId, found.id),
        fieldLabel: parsed.fieldLabel,
      };
    }

    if (parsed.fieldLabel !== null) {
      const whole = await findItemByTitle(vaultId, secretKey.trim());
      if (whole !== null) {
        return { item: await fetchItem(vaultId, whole.id), fieldLabel: null };
      }
    }

    throw new Error(
      `Item "${parsed.itemTitle}" not found in vault "${cfg.vaultId}" on ${base}. Secret keys are "item" or "item/field"; check the item title matches exactly, including case and spaces.`,
    );
  };

  return {
    get: async (secretKey: string): Promise<string> => {
      const vaultId = await resolveVaultId();
      const { item, fieldLabel } = await resolveItemForKey(vaultId, secretKey);
      const fields = item.fields ?? [];

      const target = fieldLabel === null
        ? pickDefaultField(fields, cfg.defaultFieldLabels)
        : fields.find((f) =>
          (f.label ?? "").toLowerCase() === fieldLabel.toLowerCase()
        ) ?? null;

      if (target === null || target === undefined) {
        throw new Error(
          fieldLabel === null
            ? `Item "${item.title}" has no ${
              cfg.defaultFieldLabels.join(" or ")
            } field and more than one populated field, so "${secretKey}" is ambiguous. Address a field explicitly as "${item.title}/<field>". Available fields: ${
              describeLabels(fields)
            }.`
            : `Item "${item.title}" has no field labelled "${fieldLabel}". Available fields: ${
              describeLabels(fields)
            }.`,
        );
      }

      if ((target.value ?? "") === "") {
        throw new Error(
          `Field "${
            target.label ?? target.id
          }" on item "${item.title}" is empty. Refusing to return an empty secret for "${secretKey}".`,
        );
      }
      return target.value as string;
    },

    put: async (secretKey: string, secretValue: string): Promise<void> => {
      const vaultId = await resolveVaultId();
      const parsed = parseSecretKey(secretKey);
      const label = parsed.fieldLabel ?? cfg.defaultFieldLabels[0] ??
        "password";

      const found = await findItemByTitle(vaultId, parsed.itemTitle);

      if (found === null) {
        await request<ConnectItem>(
          "POST",
          `/v1/vaults/${encodeURIComponent(vaultId)}/items`,
          {
            vault: { id: vaultId },
            title: parsed.itemTitle,
            category: cfg.itemCategory,
            fields: [
              {
                id: crypto.randomUUID().replace(/-/g, ""),
                type: "CONCEALED",
                label,
                value: secretValue,
              },
            ],
          },
        );
        return;
      }

      // Connect's item PUT is a *destructive replace*: whatever field set the
      // body carries becomes the item's entire field set. Read the detail
      // representation (the list endpoint returns no values) and send every
      // field back, with only the target one changed. Building the body from
      // anything less silently deletes the rest of the item.
      const item = await fetchItem(vaultId, found.id);
      const fields = item.fields ?? [];
      const wanted = label.toLowerCase();
      const exists = fields.some((f) =>
        (f.label ?? "").toLowerCase() === wanted
      );

      const nextFields: ConnectField[] = exists
        ? fields.map((f) =>
          (f.label ?? "").toLowerCase() === wanted
            ? { ...f, value: secretValue }
            : { ...f }
        )
        : [
          ...fields.map((f) => ({ ...f })),
          {
            id: crypto.randomUUID().replace(/-/g, ""),
            type: "CONCEALED",
            label,
            value: secretValue,
          },
        ];

      await request<ConnectItem>(
        "PUT",
        `/v1/vaults/${encodeURIComponent(vaultId)}/items/${
          encodeURIComponent(item.id)
        }`,
        { ...item, vault: { id: vaultId }, fields: nextFields },
      );
    },

    list: async (): Promise<string[]> => {
      const vaultId = await resolveVaultId();
      const items = await request<Array<{ title?: string }>>(
        "GET",
        `/v1/vaults/${encodeURIComponent(vaultId)}/items`,
      );
      if (!Array.isArray(items)) return [];
      const titles = new Set<string>();
      for (const item of items) {
        if (typeof item.title === "string" && item.title.length > 0) {
          titles.add(item.title);
        }
      }
      return [...titles].sort();
    },

    getName: (): string => name,
  };
}

/**
 * Vault type definition for 1Password Connect.
 *
 * @example Configure in `.swamp.yaml`
 * ```yaml
 * vault:
 *   type: "@sntxrr/1password-connect"
 *   config:
 *     connectHost: "https://connect.example.com"
 *     connectToken: "${OP_CONNECT_TOKEN}"
 *     vaultId: "swamp-secrets"
 * ```
 */
export const vault: {
  type: string;
  name: string;
  description: string;
  configSchema: typeof ConfigSchema;
  createProvider: (
    name: string,
    config: Record<string, unknown>,
  ) => VaultProvider;
} = {
  type: "@sntxrr/1password-connect",
  name: "1Password Connect",
  description:
    "Read and write 1Password secrets through a self-hosted Connect server over HTTP — no `op` CLI, no desktop session, so it works headless in cron, containers, and swamp serve.",
  configSchema: ConfigSchema,
  createProvider: createConnectProvider,
};
