import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ProfileStore, ProfileWatcher, planProfileChanges, type DeviceProfile } from "../src/profiles.ts";

const kids: DeviceProfile = {
  id: "p1",
  name: "KidPC",
  hostnames: ["DESKTOP-KID"],
  network: { id: "net-kids", name: "Kids" },
  speedGroup: { id: "grp-kids", name: "Kids" },
  reconnect: true,
  enabled: true,
  createdAt: "2026-10-02T00:00:00Z",
};
const NOW = new Date("2026-10-02T09:00:00Z");

test("a new MAC with a matching hostname gets the network, speed group and a name", () => {
  const active = [{ mac: "fa:00:00:00:00:01", hostname: "desktop-kid", network_id: "net-main", user_id: "u9" }];
  const [c] = planProfileChanges([kids], active, [], NOW);
  assert.equal(c.userId, "u9");
  assert.deepEqual(c.body, {
    virtual_network_override_enabled: true,
    virtual_network_override_id: "net-kids",
    usergroup_id: "grp-kids",
    name: "KidPC - MAC 00:01",
    note: 'Recognised by hostname desktop-kid; profile "KidPC" applied by unifi-mcp on 2026-10-02',
    noted: true,
  });
  assert.equal(c.reconnect, true);
});

test("compliant, non-matching and disabled cases are left alone", () => {
  const ok = { _id: "u1", mac: "aa:00:00:00:00:01", hostname: "DESKTOP-KID", virtual_network_override_enabled: true, virtual_network_override_id: "net-kids", usergroup_id: "grp-kids" };
  const other = { _id: "u2", mac: "aa:00:00:00:00:02", hostname: "DESKTOP-KID2" };
  assert.deepEqual(planProfileChanges([kids], [{ mac: ok.mac }, { mac: other.mac }], [ok, other], NOW), []);
  assert.deepEqual(planProfileChanges([{ ...kids, enabled: false }], [{ mac: "fa:00:00:00:00:01", hostname: "DESKTOP-KID", _id: "u9" }], [], NOW), []);
  // Known but offline clients are not touched.
  assert.deepEqual(planProfileChanges([kids], [], [{ _id: "u3", mac: "aa:00:00:00:00:03", hostname: "DESKTOP-KID" }], NOW), []);
});

test("partial fixes: keeps existing names, skips the override for wired clients, reconnects only when moving networks", () => {
  const named = { _id: "u1", mac: "aa:00:00:00:00:01", hostname: "DESKTOP-KID", name: "Kid PC", virtual_network_override_enabled: true, virtual_network_override_id: "net-kids", usergroup_id: "" };
  let [c] = planProfileChanges([kids], [{ mac: named.mac, network_id: "net-kids" }], [named], NOW);
  assert.deepEqual(c.body, { usergroup_id: "grp-kids" });
  assert.equal(c.reconnect, false, "speed group alone needs no reconnect");

  [c] = planProfileChanges([kids], [{ mac: "aa:00:00:00:00:04", hostname: "DESKTOP-KID", is_wired: true, _id: "u4", name: "Kid PC wired" }], [], NOW);
  assert.deepEqual(c.body, { usergroup_id: "grp-kids" });

  // Override missing but the client already sits on the target network: fix the record, don't kick.
  [c] = planProfileChanges([kids], [{ mac: "aa:00:00:00:00:05", hostname: "DESKTOP-KID", _id: "u5", name: "x", network_id: "net-kids", usergroup_id: "grp-kids" }], [], NOW);
  assert.deepEqual(c.changes, ["network → Kids"]);
  assert.equal(c.reconnect, false);
  assert.equal(planProfileChanges([{ ...kids, reconnect: false }], [{ mac: "fa:00:00:00:00:01", hostname: "DESKTOP-KID", _id: "u9", network_id: "net-main" }], [], NOW)[0].reconnect, false);
});

function harness(active: any[], known: any[] = []) {
  const store = new ProfileStore(join(mkdtempSync(join(tmpdir(), "unifi-prof-")), "profiles.json"));
  const calls: string[] = [];
  const watcher = new ProfileWatcher(
    store,
    {
      activeClients: async () => (calls.push("active"), active),
      knownClients: async () => known,
      updateClient: async (id, body) => {
        calls.push(`update ${id}`);
        const c = active.find((a) => (a._id ?? a.user_id) === id);
        Object.assign(c, body);
      },
      kick: async (mac) => void calls.push(`kick ${mac}`),
      audit: async (action) => void calls.push(action),
    },
    60_000,
  );
  return { store, watcher, calls };
}

test("watcher applies changes once, records them, and stays quiet without profiles", async () => {
  const active = [{ _id: "u9", mac: "fa:00:00:00:00:01", hostname: "DESKTOP-KID", network_id: "net-main" }];
  const { store, watcher, calls } = harness(active);
  assert.deepEqual((await watcher.run(false)).changes, []);
  assert.deepEqual(calls, [], "no console calls when there are no profiles");

  const { id: _id, createdAt: _c, ...draft } = kids;
  await store.upsert(draft);
  const dry = await watcher.run(true);
  assert.equal(dry.changes.length, 1);
  assert.equal(dry.changes[0].reconnected, true);
  assert.deepEqual(calls, ["active"], "dry run changes nothing");

  const run = await watcher.run(false);
  assert.equal(run.changes[0].mac, "fa:00:00:00:00:01");
  assert.deepEqual(calls.slice(1), ["active", "update u9", "kick fa:00:00:00:00:01", "profile_applied"]);
  assert.equal((await store.events()).length, 1);
  assert.ok(watcher.lastRunAt);

  assert.deepEqual((await watcher.run(false)).changes, [], "second run finds nothing to do");
  assert.equal(calls.filter((c) => c.startsWith("kick")).length, 1);
});

test("only one process applies changes at a time", async () => {
  const active = [{ _id: "u9", mac: "fa:00:00:00:00:01", hostname: "DESKTOP-KID", network_id: "net-main" }];
  const { store, watcher, calls } = harness(active);
  const { id: _id, createdAt: _c, ...draft } = kids;
  await store.upsert(draft);
  const release = await store.lock();
  assert.ok(release);
  assert.equal(await store.lock(), undefined, "second holder is refused");
  const skipped = await watcher.run(false);
  assert.match(skipped.skipped ?? "", /another server process/);
  assert.deepEqual(calls, []);
  assert.equal((await watcher.run(true)).changes.length, 1, "dry runs do not need the lock");
  await release();
  assert.equal((await watcher.run(false)).changes.length, 1);
  assert.ok(await store.lock(), "lock is released after a run");
});

test("a failed update is reported and retried on the next run", async () => {
  const active = [{ _id: "u9", mac: "fa:00:00:00:00:01", hostname: "DESKTOP-KID", name: "x" }];
  const { store, watcher } = harness(active);
  const { id: _id, createdAt: _c, ...draft } = kids;
  await store.upsert(draft);
  (watcher as any).deps.updateClient = async () => {
    throw new Error("console unreachable");
  };
  const run = await watcher.run(false);
  assert.equal(run.changes[0].error, "console unreachable");
  assert.equal(watcher.lastError, "console unreachable");
  assert.equal((await watcher.run(true)).changes.length, 1, "still pending");
  assert.ok(await store.lock(), "lock is released after a failed run");
});

test("profile store replaces by name and deletes by name or id", async () => {
  const { store } = harness([]);
  const { id: _id, createdAt: _c, ...draft } = kids;
  const a = await store.upsert(draft);
  const b = await store.upsert({ ...draft, name: "kidpc", hostnames: ["OTHER"] });
  assert.equal(b.id, a.id);
  assert.deepEqual((await store.list()).map((p) => p.hostnames), [["OTHER"]]);
  await assert.rejects(store.remove("nope"), /No device profile/);
  await store.remove(a.id);
  assert.deepEqual(await store.list(), []);
});
