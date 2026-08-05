/**
 * Unit tests for the 1Password Connect vault backend.
 *
 * Every Connect call is mocked — no network, no credentials, no live server.
 * The cases that matter are the ones that have bitten real deployments: vault
 * names resolving to IDs, keys containing spaces, explicit `item/field`
 * addressing, and above all `put` re-sending the complete field set, because
 * Connect's item update is a destructive replace that silently drops anything
 * the body omits.
 *
 * @module
 */
import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import { assertVaultExportConformance } from "jsr:@swamp-club/swamp-testing";
import { parseSecretKey, pickDefaultField, vault } from "./mod.ts";

const VAULT_ID = "vault1234567890abcdefghijk";
const ITEM_ID = "item1234567890abcdefghijkl";

const CONFIG_BY_NAME = {
  connectHost: "https://connect.example.com",
  connectToken: "test-token-not-a-real-jwt",
  vaultId: "swamp-secrets",
};

const CONFIG_BY_ID = { ...CONFIG_BY_NAME, vaultId: VAULT_ID };

/** One recorded Connect request. */
interface Call {
  method: string;
  url: string;
  path: string;
  filter: string | null;
  body: unknown;
}

/**
 * Swap in a mock `fetch` for the duration of `fn`, recording every call.
 */
async function withMockedFetch<T>(
  handler: (call: Call) => Response,
  fn: (calls: Call[]) => Promise<T>,
): Promise<T> {
  const original = globalThis.fetch;
  const calls: Call[] = [];
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const parsed = new URL(url);
    const call: Call = {
      method: init?.method ?? "GET",
      url,
      path: parsed.pathname,
      filter: parsed.searchParams.get("filter"),
      body: init?.body === undefined || init?.body === null
        ? undefined
        : JSON.parse(String(init.body)),
    };
    calls.push(call);
    return Promise.resolve(handler(call));
  }) as typeof globalThis.fetch;
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}

/** JSON 200 helper. */
function ok(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200 });
}

Deno.test("vault export conforms to the swamp vault contract", () => {
  assertVaultExportConformance(vault, {
    validConfigs: [CONFIG_BY_NAME, CONFIG_BY_ID],
    invalidConfigs: [
      {},
      { connectToken: "t", vaultId: "swamp-secrets" },
      { connectHost: "not-a-url", connectToken: "t", vaultId: "swamp-secrets" },
      { connectHost: "https://connect.example.com", connectToken: "" },
      { ...CONFIG_BY_ID, timeoutMs: -1 },
    ],
  });
});

Deno.test("getName returns the configured vault instance name", () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_NAME);
  assertEquals(provider.getName(), "op-connect");
});

Deno.test("parseSecretKey splits on the last slash and never on whitespace", () => {
  assertEquals(parseSecretKey("Connect Token"), {
    itemTitle: "Connect Token",
    fieldLabel: null,
  });
  assertEquals(parseSecretKey("Connect Token/api key"), {
    itemTitle: "Connect Token",
    fieldLabel: "api key",
  });
  // Item titles may themselves contain slashes.
  assertEquals(parseSecretKey("infra/prod db/password"), {
    itemTitle: "infra/prod db",
    fieldLabel: "password",
  });
  // Degenerate separators are not separators.
  assertEquals(parseSecretKey("/leading"), {
    itemTitle: "/leading",
    fieldLabel: null,
  });
  assertEquals(parseSecretKey("trailing/"), {
    itemTitle: "trailing/",
    fieldLabel: null,
  });
});

Deno.test("pickDefaultField prefers password, then credential, then a lone populated field", () => {
  const both = [
    { id: "a", label: "credential", value: "c" },
    { id: "b", label: "password", value: "p" },
  ];
  assertEquals(pickDefaultField(both, ["password", "credential"])?.value, "p");

  const credentialOnly = [{ id: "a", label: "credential", value: "c" }];
  assertEquals(
    pickDefaultField(credentialOnly, ["password", "credential"])?.value,
    "c",
  );

  // A Login item's password field is matched by purpose even when relabelled.
  const byPurpose = [{
    id: "a",
    label: "PIN",
    purpose: "PASSWORD",
    value: "p",
  }];
  assertEquals(pickDefaultField(byPurpose, ["password"])?.value, "p");

  // Empty NOTES fields must not count as "the lone field".
  const lone = [
    { id: "a", label: "token", value: "t" },
    { id: "b", label: "notesPlain", purpose: "NOTES", value: "" },
  ];
  assertEquals(pickDefaultField(lone, ["password", "credential"])?.value, "t");

  const ambiguous = [
    { id: "a", label: "one", value: "1" },
    { id: "b", label: "two", value: "2" },
  ];
  assertEquals(pickDefaultField(ambiguous, ["password"]), null);
});

Deno.test("a vault name is resolved to a vault ID and reused for item routes", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_NAME);
  const value = await withMockedFetch(
    (call) => {
      if (call.path === "/v1/vaults") {
        return ok([{ id: VAULT_ID, name: "swamp-secrets" }]);
      }
      if (call.path === `/v1/vaults/${VAULT_ID}/items`) {
        return ok([{ id: ITEM_ID, title: "Cloudflare API" }]);
      }
      return ok({
        id: ITEM_ID,
        title: "Cloudflare API",
        vault: { id: VAULT_ID },
        category: "LOGIN",
        fields: [{ id: "f1", label: "password", value: "s3cr3t" }],
      });
    },
    async (calls) => {
      const first = await provider.get("Cloudflare API");
      // Second read must not re-resolve the vault name.
      await provider.get("Cloudflare API");
      assertEquals(
        calls.filter((c) => c.path === "/v1/vaults").length,
        1,
        "vault ID resolution must be cached per provider",
      );
      assertEquals(calls[0].filter, 'title eq "swamp-secrets"');
      return first;
    },
  );
  assertEquals(value, "s3cr3t");
});

Deno.test("an ID-shaped vaultId is verified once and used directly", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      return ok([{ id: ITEM_ID, title: "x" }, { id: "z", title: "a" }]);
    },
    async (calls) => {
      const titles = await provider.list();
      assertEquals(titles, ["a", "x"]);
      // No filtered /v1/vaults name lookup happened.
      assert(
        calls.every((c) => c.filter === null),
        "an ID-shaped vaultId must skip the name filter lookup",
      );
    },
  );
});

Deno.test("keys containing spaces address the right item and field", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  const value = await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      if (call.path === `/v1/vaults/${VAULT_ID}/items`) {
        return ok([{ id: ITEM_ID, title: "backup service" }]);
      }
      return ok({
        id: ITEM_ID,
        title: "backup service",
        vault: { id: VAULT_ID },
        category: "LOGIN",
        fields: [
          { id: "f1", label: "password", value: "wrong-field" },
          { id: "f2", label: "api key", value: "right-field" },
        ],
      });
    },
    async (calls) => {
      const got = await provider.get("backup service/api key");
      const itemQuery = calls.find((c) =>
        c.path === `/v1/vaults/${VAULT_ID}/items`
      );
      assertEquals(
        itemQuery?.filter,
        'title eq "backup service"',
        "the item title must keep its spaces, not be split on them",
      );
      return got;
    },
  );
  assertEquals(value, "right-field");
});

Deno.test("a bare key with spaces falls back to the default field", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  const value = await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      if (call.path === `/v1/vaults/${VAULT_ID}/items`) {
        return ok([{ id: ITEM_ID, title: "home network" }]);
      }
      return ok({
        id: ITEM_ID,
        title: "home network",
        vault: { id: VAULT_ID },
        category: "LOGIN",
        fields: [
          { id: "f1", label: "username", value: "someone" },
          { id: "f2", label: "password", value: "default-hit" },
        ],
      });
    },
    () => provider.get("home network"),
  );
  assertEquals(value, "default-hit");
});

Deno.test("get reports the fields that exist when the named one does not", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      if (call.path === `/v1/vaults/${VAULT_ID}/items`) {
        return ok([{ id: ITEM_ID, title: "Cloudflare API" }]);
      }
      return ok({
        id: ITEM_ID,
        title: "Cloudflare API",
        vault: { id: VAULT_ID },
        category: "LOGIN",
        fields: [{ id: "f1", label: "password", value: "p" }],
      });
    },
    async () => {
      let message = "";
      try {
        await provider.get("Cloudflare API/api key");
      } catch (error) {
        message = (error as Error).message;
      }
      assertStringIncludes(message, 'no field labelled "api key"');
      assertStringIncludes(message, "password");
    },
  );
});

Deno.test("put re-sends every existing field, so an update never drops one", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      if (call.method === "GET" && call.path.endsWith("/items")) {
        return ok([{ id: ITEM_ID, title: "Cloudflare API" }]);
      }
      if (call.method === "GET") {
        return ok({
          id: ITEM_ID,
          title: "Cloudflare API",
          vault: { id: VAULT_ID },
          category: "LOGIN",
          sections: [{ id: "sec1", label: "extras" }],
          fields: [
            { id: "f1", label: "username", value: "someone@example.com" },
            { id: "f2", label: "password", value: "old-password" },
            {
              id: "f3",
              label: "account id",
              value: "192.0.2.7",
              section: { id: "sec1" },
            },
          ],
        });
      }
      return ok({ id: ITEM_ID });
    },
    async (calls) => {
      await provider.put("Cloudflare API/password", "new-password");

      const put = calls.find((c) => c.method === "PUT");
      assert(put, "an existing item must be updated with PUT");
      const body = put.body as {
        id: string;
        title: string;
        category: string;
        vault: { id: string };
        sections?: Array<{ id: string }>;
        fields: Array<
          {
            id: string;
            label: string;
            value?: string;
            section?: { id: string };
          }
        >;
      };

      // The destructive-replace trap: all three fields must come back.
      assertEquals(body.fields.length, 3);
      assertEquals(
        body.fields.find((f) => f.label === "username")?.value,
        "someone@example.com",
      );
      assertEquals(
        body.fields.find((f) => f.label === "account id")?.value,
        "192.0.2.7",
      );
      assertEquals(
        body.fields.find((f) => f.label === "account id")?.section?.id,
        "sec1",
        "section membership must survive the round trip",
      );
      assertEquals(
        body.fields.find((f) => f.label === "password")?.value,
        "new-password",
      );
      // Item identity and sections must survive too.
      assertEquals(body.id, ITEM_ID);
      assertEquals(body.title, "Cloudflare API");
      assertEquals(body.category, "LOGIN");
      assertEquals(body.vault.id, VAULT_ID);
      assertEquals(body.sections?.[0].id, "sec1");

      // The item detail endpoint must be what the PUT was built from — the
      // list endpoint returns no values and would blank the item.
      assert(
        calls.some((c) =>
          c.method === "GET" &&
          c.path === `/v1/vaults/${VAULT_ID}/items/${ITEM_ID}`
        ),
        "put must read the item detail endpoint before writing",
      );
    },
  );
});

Deno.test("put appends a new field to an existing item without disturbing the others", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      if (call.method === "GET" && call.path.endsWith("/items")) {
        return ok([{ id: ITEM_ID, title: "Cloudflare API" }]);
      }
      if (call.method === "GET") {
        return ok({
          id: ITEM_ID,
          title: "Cloudflare API",
          vault: { id: VAULT_ID },
          category: "LOGIN",
          fields: [{ id: "f1", label: "password", value: "keep-me" }],
        });
      }
      return ok({ id: ITEM_ID });
    },
    async (calls) => {
      await provider.put("Cloudflare API/api key", "brand-new");
      const body = calls.find((c) => c.method === "PUT")?.body as {
        fields: Array<{ label: string; value: string; type?: string }>;
      };
      assertEquals(body.fields.length, 2);
      assertEquals(
        body.fields.find((f) => f.label === "password")?.value,
        "keep-me",
      );
      const added = body.fields.find((f) => f.label === "api key");
      assertEquals(added?.value, "brand-new");
      assertEquals(added?.type, "CONCEALED");
    },
  );
});

Deno.test("put creates the item when it does not exist yet", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      if (call.method === "GET") return ok([]);
      return ok({ id: "created" });
    },
    async (calls) => {
      await provider.put("brand new item", "hunter2");
      const post = calls.find((c) => c.method === "POST");
      assert(post, "a missing item must be created with POST");
      const body = post.body as {
        title: string;
        category: string;
        vault: { id: string };
        fields: Array<{ label: string; value: string }>;
      };
      assertEquals(body.title, "brand new item");
      assertEquals(body.category, "LOGIN");
      assertEquals(body.vault.id, VAULT_ID);
      assertEquals(body.fields[0].label, "password");
      assertEquals(body.fields[0].value, "hunter2");
      assert(
        calls.every((c) => c.method !== "PUT"),
        "creating an item must not also issue a destructive PUT",
      );
    },
  );
});

Deno.test("a 401 produces an actionable token error and never echoes the token", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_NAME);
  await withMockedFetch(
    () => new Response("Invalid token signature", { status: 401 }),
    async () => {
      let message = "";
      try {
        await provider.get("anything");
      } catch (error) {
        message = (error as Error).message;
      }
      assertStringIncludes(message, "401");
      assertStringIncludes(message, "connectToken");
      assertStringIncludes(message, "expired");
      assert(
        !message.includes(CONFIG_BY_NAME.connectToken),
        "the token must never appear in an error message",
      );
    },
  );
});

Deno.test("a vault the token cannot see explains the Connect grant model", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_NAME);
  await withMockedFetch(
    // Connect answers a filter for an ungranted vault with an empty list.
    () => ok([]),
    async () => {
      let message = "";
      try {
        await provider.get("anything");
      } catch (error) {
        message = (error as Error).message;
      }
      assertStringIncludes(message, 'Vault "swamp-secrets" was not found');
      assertStringIncludes(message, "no access");
      assertStringIncludes(message, "Private/Personal/Employee");
    },
  );
});

Deno.test("a 403 on an ID-shaped vault explains the missing grant", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  await withMockedFetch(
    () => new Response("no access", { status: 403 }),
    async () => {
      let message = "";
      try {
        await provider.list();
      } catch (error) {
        message = (error as Error).message;
      }
      assertStringIncludes(message, "403");
      assertStringIncludes(message, "was not granted this vault");
    },
  );
});

Deno.test("get refuses to return an empty field value", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      if (call.path === `/v1/vaults/${VAULT_ID}/items`) {
        return ok([{ id: ITEM_ID, title: "empty item" }]);
      }
      return ok({
        id: ITEM_ID,
        title: "empty item",
        vault: { id: VAULT_ID },
        category: "LOGIN",
        fields: [{ id: "f1", label: "password", value: "" }],
      });
    },
    async () => {
      let message = "";
      try {
        await provider.get("empty item/password");
      } catch (error) {
        message = (error as Error).message;
      }
      assertStringIncludes(message, "is empty");
    },
  );
});

Deno.test("list returns de-duplicated, sorted item titles and no values", async () => {
  const provider = vault.createProvider("op-connect", CONFIG_BY_ID);
  const titles = await withMockedFetch(
    (call) => {
      if (call.path === `/v1/vaults/${VAULT_ID}`) return ok({ id: VAULT_ID });
      return ok([
        { id: "1", title: "zeta" },
        { id: "2", title: "alpha" },
        { id: "3", title: "alpha" },
      ]);
    },
    () => provider.list(),
  );
  assertEquals(titles, ["alpha", "zeta"]);
  assert(titles.every((t) => typeof t === "string"));
});
