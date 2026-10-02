import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { LegacyClient } from "./legacy.js";

/** Internal-API reference to a network (rest/networkconf) or speed group (rest/usergroup). */
export interface ProfileRef {
  id: string;
  name: string;
}

/**
 * Settings to enforce on a device that is recognised by hostname, whatever MAC address it uses
 * (e.g. a PC that rejoins Wi-Fi with a new randomized MAC to dodge its restrictions).
 */
export interface DeviceProfile {
  id: string;
  name: string;
  /** Exact hostnames, compared case-insensitively. */
  hostnames: string[];
  /** Wi-Fi network override ("virtual network override") to apply. */
  network?: ProfileRef;
  /** Speed-limit group to apply. */
  speedGroup?: ProfileRef;
  /** Kick the device after changing its network so the override takes effect. */
  reconnect: boolean;
  enabled: boolean;
  createdAt: string;
}

export interface ProfileEvent {
  at: string;
  profile: string;
  mac: string;
  hostname?: string;
  changes: string[];
  reconnected: boolean;
  error?: string;
}

export interface ProfileChange {
  profile: DeviceProfile;
  mac: string;
  hostname?: string;
  userId: string;
  /** Fields to PUT to rest/user/{userId}. */
  body: Record<string, unknown>;
  changes: string[];
  reconnect: boolean;
}

/**
 * Work out which connected clients match a profile but lack its settings. Pure: no I/O.
 * Only connected clients are considered, so old records are left as the user set them.
 */
export function planProfileChanges(profiles: DeviceProfile[], active: LegacyClient[], known: LegacyClient[], now = new Date()): ProfileChange[] {
  const knownByMac = new Map(known.map((c) => [c.mac, c]));
  const out: ProfileChange[] = [];
  const seen = new Set<string>();
  for (const profile of profiles) {
    if (!profile.enabled) continue;
    const names = new Set(profile.hostnames.map((h) => h.toLowerCase()));
    for (const live of active) {
      const record = knownByMac.get(live.mac);
      const c: LegacyClient = { ...record, ...live };
      const hostname = c.hostname ? String(c.hostname) : undefined;
      if (!hostname || !names.has(hostname.toLowerCase()) || seen.has(c.mac)) continue;
      const userId = String(record?._id ?? live.user_id ?? live._id ?? "");
      if (!userId) continue;

      const body: Record<string, unknown> = {};
      const changes: string[] = [];
      let networkChanged = false;
      // The network override only exists for Wi-Fi clients; wired ones follow their switch port.
      if (profile.network && !c.is_wired) {
        if (c.virtual_network_override_enabled !== true || c.virtual_network_override_id !== profile.network.id) {
          body.virtual_network_override_enabled = true;
          body.virtual_network_override_id = profile.network.id;
          changes.push(`network → ${profile.network.name}`);
          networkChanged = true;
        }
      }
      if (profile.speedGroup && c.usergroup_id !== profile.speedGroup.id) {
        body.usergroup_id = profile.speedGroup.id;
        changes.push(`speed group → ${profile.speedGroup.name}`);
      }
      if (!changes.length) continue;
      if (!c.name) {
        body.name = `${profile.name} - MAC ${c.mac.slice(-5)}`;
        body.note = `Recognised by hostname ${hostname}; profile "${profile.name}" applied by unifi-mcp on ${now.toISOString().slice(0, 10)}`;
        body.noted = true;
        changes.push(`named "${body.name}"`);
      }
      seen.add(c.mac);
      out.push({
        profile,
        mac: c.mac,
        hostname,
        userId,
        body,
        changes,
        reconnect: profile.reconnect && networkChanged && c.network_id !== profile.network!.id,
      });
    }
  }
  return out;
}

interface ProfileFile {
  profiles: DeviceProfile[];
  events: ProfileEvent[];
}

const KEEP_EVENTS = 50;
const LOCK_STALE_MS = 60_000;

/** Device profiles and recent watcher events, persisted as one JSON file. */
export class ProfileStore {
  constructor(private readonly file: string) {}

  private async read(): Promise<ProfileFile> {
    try {
      const data = JSON.parse(await readFile(this.file, "utf8")) as Partial<ProfileFile>;
      return { profiles: Array.isArray(data.profiles) ? data.profiles : [], events: Array.isArray(data.events) ? data.events : [] };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") console.error(`profiles: cannot read ${this.file}: ${(err as Error).message}`);
      return { profiles: [], events: [] };
    }
  }

  private async write(data: ProfileFile): Promise<void> {
    await mkdir(dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(data, null, 2));
    await rename(tmp, this.file);
  }

  async list(): Promise<DeviceProfile[]> {
    return (await this.read()).profiles;
  }

  async events(): Promise<ProfileEvent[]> {
    return (await this.read()).events;
  }

  /** Create a profile, or replace the one with the same name (case-insensitive). */
  async upsert(p: Omit<DeviceProfile, "id" | "createdAt">): Promise<DeviceProfile> {
    const data = await this.read();
    const i = data.profiles.findIndex((x) => x.name.toLowerCase() === p.name.toLowerCase());
    const full: DeviceProfile =
      i >= 0 ? { ...p, id: data.profiles[i].id, createdAt: data.profiles[i].createdAt } : { ...p, id: randomUUID().slice(0, 8), createdAt: new Date().toISOString() };
    if (i >= 0) data.profiles[i] = full;
    else data.profiles.push(full);
    await this.write(data);
    return full;
  }

  async remove(nameOrId: string): Promise<DeviceProfile> {
    const data = await this.read();
    const k = nameOrId.toLowerCase();
    const i = data.profiles.findIndex((x) => x.id === nameOrId || x.name.toLowerCase() === k);
    if (i < 0) throw new Error(`No device profile "${nameOrId}". Use unifi_list_device_profiles to see them.`);
    const [gone] = data.profiles.splice(i, 1);
    await this.write(data);
    return gone;
  }

  /**
   * Cross-process lock so two servers sharing the file (e.g. the HTTP service and a stdio session)
   * do not apply the same change twice. Returns a release function, or undefined if another
   * process holds the lock. A lock older than a minute is treated as left behind by a crash.
   */
  async lock(): Promise<(() => Promise<void>) | undefined> {
    const path = `${this.file}.lock`;
    await mkdir(dirname(this.file), { recursive: true });
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await writeFile(path, String(process.pid), { flag: "wx" });
        return () => rm(path, { force: true });
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
        const age = await stat(path).then((s) => Date.now() - s.mtimeMs, () => 0);
        if (age < LOCK_STALE_MS) return undefined;
        await rm(path, { force: true });
      }
    }
    return undefined;
  }

  async addEvents(events: ProfileEvent[]): Promise<void> {
    if (!events.length) return;
    const data = await this.read();
    data.events = [...data.events, ...events].slice(-KEEP_EVENTS);
    await this.write(data);
  }
}

export interface WatcherDeps {
  activeClients(): Promise<LegacyClient[]>;
  knownClients(): Promise<LegacyClient[]>;
  updateClient(userId: string, body: Record<string, unknown>): Promise<unknown>;
  kick(mac: string): Promise<unknown>;
  audit(action: string, details: Record<string, unknown>): Promise<void>;
}

export interface WatcherRun {
  checkedAt: string;
  profiles: number;
  dryRun: boolean;
  changes: ProfileEvent[];
  /** Set when nothing was done because another server process was mid-check. */
  skipped?: string;
}

/**
 * Periodically applies device profiles to connected clients. Applying is idempotent (a client that
 * already has the settings is left alone), so several server processes may run it side by side.
 */
export class ProfileWatcher {
  private timer?: NodeJS.Timeout;
  private running = false;
  lastRunAt?: string;
  lastError?: string;

  constructor(
    private readonly store: ProfileStore,
    private readonly deps: WatcherDeps,
    readonly intervalMs: number,
  ) {}

  start(): void {
    if (this.timer) return;
    void this.tick();
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
    this.timer.unref(); // never keep a stdio server alive just for the watcher
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  private async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      await this.run(false);
    } catch (err) {
      this.lastError = (err as Error).message;
      console.error(`profile watcher: ${this.lastError}`);
    } finally {
      this.running = false;
    }
  }

  /** Check now. With dryRun, report what would change without touching the console. */
  async run(dryRun: boolean): Promise<WatcherRun> {
    const checkedAt = new Date().toISOString();
    const profiles = (await this.store.list()).filter((p) => p.enabled);
    const result: WatcherRun = { checkedAt, profiles: profiles.length, dryRun, changes: [] };
    // No profiles: stay silent rather than polling the console for nothing.
    if (!profiles.length) return result;
    const release = dryRun ? undefined : await this.store.lock();
    if (!dryRun && !release) return { ...result, skipped: "another server process is checking right now" };
    try {
      const [active, known] = await Promise.all([this.deps.activeClients(), this.deps.knownClients()]);
      for (const ch of planProfileChanges(profiles, active, known)) {
        const event: ProfileEvent = { at: checkedAt, profile: ch.profile.name, mac: ch.mac, hostname: ch.hostname, changes: ch.changes, reconnected: false };
        if (!dryRun) {
          try {
            await this.deps.updateClient(ch.userId, ch.body);
            if (ch.reconnect) {
              await this.deps.kick(ch.mac);
              event.reconnected = true;
            }
            await this.deps.audit("profile_applied", { profile: ch.profile.name, mac: ch.mac, hostname: ch.hostname, changes: ch.changes, reconnected: event.reconnected });
          } catch (err) {
            event.error = (err as Error).message;
          }
        } else {
          event.reconnected = ch.reconnect;
        }
        result.changes.push(event);
      }
      if (!dryRun) await this.store.addEvents(result.changes);
    } finally {
      await release?.();
    }
    if (!dryRun) {
      this.lastRunAt = checkedAt;
      this.lastError = result.changes.find((c) => c.error)?.error;
    }
    return result;
  }
}
