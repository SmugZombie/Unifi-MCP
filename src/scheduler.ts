import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export type JobAction = "unblock_client" | "delete_firewall_policy";

export interface ScheduledJob {
  id: string;
  action: JobAction;
  args: Record<string, string>;
  /** Human-readable description, e.g. "Unblock TV (aa:bb:…)". */
  label: string;
  reason?: string;
  runAt: string;
  createdAt: string;
  status: "pending" | "done" | "failed" | "cancelled";
  attempts: number;
  lastError?: string;
  finishedAt?: string;
}

export type JobRunner = (job: ScheduledJob) => Promise<void>;

const MAX_ATTEMPTS = 5;
const RETRY_MS = 2 * 60_000;
const KEEP_HISTORY_MS = 7 * 24 * 3600_000;

/**
 * Persistent one-shot jobs that undo temporary changes (timed blocks). Jobs are stored in a JSON
 * file so they survive restarts; overdue jobs run on the next check. Actions must be idempotent:
 * several server processes may share the file and could run the same job.
 */
export class Scheduler {
  private jobs: ScheduledJob[] = [];
  private timer?: NodeJS.Timeout;
  private ticking = false;

  constructor(
    private readonly file: string,
    private readonly runner: JobRunner,
    private readonly intervalMs = 30_000,
  ) {}

  private async load(): Promise<void> {
    try {
      this.jobs = JSON.parse(await readFile(this.file, "utf8"));
      if (!Array.isArray(this.jobs)) this.jobs = [];
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") console.error(`scheduler: cannot read ${this.file}: ${(err as Error).message}`);
      this.jobs = [];
    }
  }

  private async save(): Promise<void> {
    const cutoff = Date.now() - KEEP_HISTORY_MS;
    this.jobs = this.jobs.filter((j) => j.status === "pending" || Date.parse(j.finishedAt ?? j.runAt) > cutoff);
    await mkdir(dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(this.jobs, null, 2));
    await rename(tmp, this.file);
  }

  start(): void {
    if (this.timer) return;
    void this.tick();
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
    this.timer.unref(); // never keep a stdio server alive just for the scheduler
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  async add(job: Pick<ScheduledJob, "action" | "args" | "label" | "reason" | "runAt">): Promise<ScheduledJob> {
    await this.load();
    const full: ScheduledJob = { ...job, id: randomUUID().slice(0, 8), createdAt: new Date().toISOString(), status: "pending", attempts: 0 };
    this.jobs.push(full);
    await this.save();
    return full;
  }

  async list(includeHistory = false): Promise<ScheduledJob[]> {
    await this.load();
    return this.jobs
      .filter((j) => includeHistory || j.status === "pending")
      .sort((a, b) => a.runAt.localeCompare(b.runAt));
  }

  /** Cancel a pending job; with runNow, perform its action immediately instead of waiting. */
  async cancel(id: string, runNow: boolean): Promise<ScheduledJob> {
    await this.load();
    const job = this.jobs.find((j) => j.id === id);
    if (!job) throw new Error(`No scheduled action with id ${id}`);
    if (job.status !== "pending") throw new Error(`Scheduled action ${id} is already ${job.status}`);
    if (runNow) {
      await this.runner(job);
      job.status = "done";
    } else {
      job.status = "cancelled";
    }
    job.finishedAt = new Date().toISOString();
    await this.save();
    return job;
  }

  /** Run due jobs. Exposed for tests. */
  async tick(): Promise<void> {
    if (this.ticking) return;
    this.ticking = true;
    try {
      await this.load();
      const now = Date.now();
      const due = this.jobs.filter((j) => j.status === "pending" && Date.parse(j.runAt) <= now);
      if (!due.length) return;
      for (const job of due) {
        job.attempts += 1;
        try {
          await this.runner(job);
          job.status = "done";
          job.finishedAt = new Date().toISOString();
          delete job.lastError;
        } catch (err) {
          job.lastError = (err as Error).message;
          if (job.attempts >= MAX_ATTEMPTS) {
            job.status = "failed";
            job.finishedAt = new Date().toISOString();
            console.error(`scheduler: giving up on ${job.label}: ${job.lastError}`);
          } else {
            job.runAt = new Date(now + RETRY_MS).toISOString();
          }
        }
      }
      // Merge with any jobs another process added meanwhile.
      const mine = new Map(due.map((j) => [j.id, j]));
      await this.load();
      this.jobs = this.jobs.map((j) => mine.get(j.id) ?? j);
      await this.save();
    } catch (err) {
      console.error(`scheduler: ${(err as Error).message}`);
    } finally {
      this.ticking = false;
    }
  }
}

/** Milliseconds to add to UTC to get wall-clock time in `tz` at instant `t`. */
function tzOffsetMs(t: number, tz: string): number {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" })
      .formatToParts(new Date(t))
      .map((p) => [p.type, Number(p.value)]),
  );
  return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) - Math.floor(t / 1000) * 1000;
}

/** Next instant (after `now`) when the wall clock in `tz` reads HH:MM. */
export function nextWallClock(hhmm: string, tz: string, now = Date.now()): Date {
  const m = hhmm.trim().match(/^([01]?\d|2[0-3]):([0-5]\d)$/);
  if (!m) throw new Error(`untilTime must be HH:MM in 24-hour time, e.g. "06:00" (got "${hhmm}")`);
  const local = new Date(now + tzOffsetMs(now, tz)); // fields read as UTC = wall clock in tz
  for (let addDays = 0; addDays <= 2; addDays++) {
    const wall = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate() + addDays, Number(m[1]), Number(m[2]));
    // Convert wall clock back to an instant; re-check the offset once for DST transitions.
    let t = wall - tzOffsetMs(wall, tz);
    t = wall - tzOffsetMs(t, tz);
    if (t > now) return new Date(t);
  }
  throw new Error(`Could not compute next ${hhmm} in ${tz}`);
}

export interface ExpiryArgs {
  until?: string;
  untilTime?: string;
  durationMinutes?: number;
}

/** Resolve until / untilTime / durationMinutes into an absolute time, or undefined for "no expiry". */
export function expiryFrom(args: ExpiryArgs, tz: string, now = Date.now()): Date | undefined {
  const given = [args.until, args.untilTime, args.durationMinutes].filter((v) => v !== undefined && v !== "");
  if (given.length > 1) throw new Error("Pass only one of until, untilTime or durationMinutes");
  let t: number | undefined;
  if (args.durationMinutes) t = now + args.durationMinutes * 60_000;
  else if (args.untilTime) t = nextWallClock(args.untilTime, tz, now).getTime();
  else if (args.until) {
    t = Date.parse(args.until);
    if (Number.isNaN(t)) throw new Error("until must be an ISO 8601 timestamp with a timezone offset, e.g. 2026-10-03T06:00:00-07:00");
    if (t <= now) throw new Error("until is in the past");
  }
  if (t === undefined) return undefined;
  if (t - now > 31 * 24 * 3600_000) throw new Error("Expiry must be within 31 days");
  return new Date(t);
}

/** Format an instant in the console's timezone for messages, e.g. "2026-10-03 06:00 (America/Phoenix)". */
export function formatInZone(d: Date, tz: string): string {
  const s = new Intl.DateTimeFormat("sv-SE", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(d);
  return `${s} (${tz})`;
}
