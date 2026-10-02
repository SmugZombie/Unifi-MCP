import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Scheduler, expiryFrom, nextWallClock, type ScheduledJob } from "../src/scheduler.ts";

const NOW = Date.parse("2026-10-02T09:30:00Z"); // 02:30 in Phoenix (UTC-7, no DST)

test("nextWallClock picks the next occurrence in the console timezone", () => {
  assert.equal(nextWallClock("06:00", "America/Phoenix", NOW).toISOString(), "2026-10-02T13:00:00.000Z");
  assert.equal(nextWallClock("01:00", "America/Phoenix", NOW).toISOString(), "2026-10-03T08:00:00.000Z");
  assert.equal(nextWallClock("6:00", "America/New_York", NOW).toISOString(), "2026-10-02T10:00:00.000Z");
  // New York springs forward on 2027-03-14; 06:00 that day is EDT (UTC-4).
  assert.equal(nextWallClock("06:00", "America/New_York", Date.parse("2027-03-14T05:00:00Z")).toISOString(), "2027-03-14T10:00:00.000Z");
  assert.throws(() => nextWallClock("6am", "America/Phoenix", NOW), /HH:MM/);
  assert.throws(() => nextWallClock("24:00", "America/Phoenix", NOW), /HH:MM/);
});

test("expiryFrom validates its inputs", () => {
  assert.equal(expiryFrom({}, "UTC", NOW), undefined);
  assert.equal(expiryFrom({ durationMinutes: 90 }, "UTC", NOW)?.toISOString(), "2026-10-02T11:00:00.000Z");
  assert.equal(expiryFrom({ untilTime: "06:00" }, "America/Phoenix", NOW)?.toISOString(), "2026-10-02T13:00:00.000Z");
  assert.equal(expiryFrom({ until: "2026-10-03T06:00:00-07:00" }, "UTC", NOW)?.toISOString(), "2026-10-03T13:00:00.000Z");
  assert.throws(() => expiryFrom({ until: "2026-10-01T00:00:00Z" }, "UTC", NOW), /past/);
  assert.throws(() => expiryFrom({ until: "tomorrow" }, "UTC", NOW), /ISO 8601/);
  assert.throws(() => expiryFrom({ durationMinutes: 10, untilTime: "06:00" }, "UTC", NOW), /only one/);
  assert.throws(() => expiryFrom({ until: "2026-12-01T00:00:00Z" }, "UTC", NOW), /31 days/);
});

function scheduler(runner: (j: ScheduledJob) => Promise<void>) {
  const file = join(mkdtempSync(join(tmpdir(), "unifi-sched-")), "jobs.json");
  return { file, s: new Scheduler(file, runner, 60_000) };
}

test("scheduler persists jobs and runs them when due", async () => {
  const ran: string[] = [];
  const { file, s } = scheduler(async (j) => void ran.push(j.args.mac));
  const past = new Date(Date.now() - 1000).toISOString();
  const future = new Date(Date.now() + 3600_000).toISOString();
  await s.add({ action: "unblock_client", args: { mac: "aa" }, label: "a", runAt: past });
  await s.add({ action: "unblock_client", args: { mac: "bb" }, label: "b", runAt: future });
  // A second instance sharing the file sees both jobs (survives restarts).
  const other = new Scheduler(file, async () => {}, 60_000);
  assert.equal((await other.list()).length, 2);

  await s.tick();
  assert.deepEqual(ran, ["aa"]);
  assert.deepEqual((await s.list()).map((j) => j.label), ["b"]);
  const stored = JSON.parse(readFileSync(file, "utf8")) as ScheduledJob[];
  assert.equal(stored.find((j) => j.label === "a")?.status, "done");
});

test("scheduler retries failures, then gives up", async () => {
  let calls = 0;
  const { s } = scheduler(async () => {
    calls++;
    throw new Error("console unreachable");
  });
  const job = await s.add({ action: "unblock_client", args: { mac: "aa" }, label: "a", runAt: new Date(Date.now() - 1000).toISOString() });
  await s.tick();
  let [j] = await s.list(true);
  assert.equal(j.status, "pending", "still pending after first failure");
  assert.equal(j.lastError, "console unreachable");
  assert.ok(Date.parse(j.runAt) > Date.now(), "retry is pushed into the future");
  for (let i = 0; i < 4; i++) {
    // Make it due again and retry.
    const jobs = await s.list(true);
    jobs[0].runAt = new Date(Date.now() - 1000).toISOString();
    (s as any).jobs = jobs;
    await (s as any).save();
    await s.tick();
  }
  [j] = await s.list(true);
  assert.equal(j.id, job.id);
  assert.equal(j.status, "failed");
  assert.equal(calls, 5);
});

test("cancel keeps the change or runs it now", async () => {
  const ran: string[] = [];
  const { s } = scheduler(async (j) => void ran.push(j.label));
  const future = new Date(Date.now() + 3600_000).toISOString();
  const a = await s.add({ action: "unblock_client", args: { mac: "aa" }, label: "a", runAt: future });
  const b = await s.add({ action: "unblock_client", args: { mac: "bb" }, label: "b", runAt: future });
  assert.equal((await s.cancel(a.id, false)).status, "cancelled");
  assert.equal((await s.cancel(b.id, true)).status, "done");
  assert.deepEqual(ran, ["b"]);
  await assert.rejects(s.cancel(a.id, true), /already cancelled/);
  await assert.rejects(s.cancel("nope", true), /No scheduled action/);
  assert.equal((await s.list()).length, 0);
});
