import { HttpTransport, UnifiApiError, type RequestOptions } from "./http.js";

interface LegacyEnvelope<T> {
  meta: { rc: "ok" | "error"; msg?: string };
  data: T[];
}

/** A client record from the internal API (rest/user or stat/sta). Only commonly used fields are typed. */
export interface LegacyClient {
  _id?: string;
  mac: string;
  name?: string;
  hostname?: string;
  oui?: string;
  ip?: string;
  last_ip?: string;
  fixed_ip?: string;
  use_fixedip?: boolean;
  network?: string;
  network_id?: string;
  last_connection_network_name?: string;
  essid?: string;
  is_wired?: boolean;
  is_guest?: boolean;
  blocked?: boolean;
  noted?: boolean;
  note?: string;
  first_seen?: number;
  last_seen?: number;
  uptime?: number;
  signal?: number;
  satisfaction?: number;
  "tx_bytes"?: number;
  "rx_bytes"?: number;
  [key: string]: unknown;
}

type AuthMode = "apikey" | "session";

/**
 * Client for the internal ("classic") UniFi Network API at /proxy/network/api/s/{site}.
 * Needed for operations the official API does not offer, notably blocking clients.
 *
 * Authenticates with the API key when possible and falls back to a local-admin
 * session (cookie + CSRF token) if the key is rejected and credentials are configured.
 */
export class LegacyApiClient {
  private mode: AuthMode;
  private cookie?: string;
  private csrf?: string;

  constructor(
    private readonly http: HttpTransport,
    private readonly creds: { apiKey?: string; username?: string; password?: string },
    private readonly siteRef: () => Promise<string>,
  ) {
    this.mode = creds.apiKey ? "apikey" : "session";
  }

  private get hasSessionCreds(): boolean {
    return Boolean(this.creds.username && this.creds.password);
  }

  private async login(): Promise<void> {
    const path = "/api/auth/login";
    const res = await this.http.raw(path, {
      method: "POST",
      body: { username: this.creds.username, password: this.creds.password, rememberMe: true },
    });
    await HttpTransport.decode(res, "POST", path);
    const token = res.headers
      .getSetCookie()
      .map((c) => c.split(";")[0])
      .find((c) => c.startsWith("TOKEN="));
    if (!token) throw new Error("Login succeeded but no session cookie was returned");
    this.cookie = token;
    this.csrf = res.headers.get("x-csrf-token") ?? undefined;
  }

  private authHeaders(): Record<string, string> {
    if (this.mode === "apikey") return { "X-API-KEY": this.creds.apiKey! };
    const h: Record<string, string> = {};
    if (this.cookie) h.Cookie = this.cookie;
    if (this.csrf) h["X-CSRF-Token"] = this.csrf;
    return h;
  }

  private async send(path: string, opts: RequestOptions) {
    if (this.mode === "session" && !this.cookie) await this.login();
    const res = await this.http.raw(path, { ...opts, headers: { ...opts.headers, ...this.authHeaders() } });
    const updated = res.headers.get("x-updated-csrf-token");
    if (updated) this.csrf = updated;
    return res;
  }

  async request<T = unknown>(subPath: string, opts: RequestOptions = {}): Promise<T[]> {
    const path = `/proxy/network/api/s/${await this.siteRef()}${subPath}`;
    const method = opts.method ?? "GET";
    let res = await this.send(path, opts);

    if (res.status === 401 || res.status === 403) {
      await res.body?.cancel();
      if (this.mode === "apikey" && this.hasSessionCreds) {
        // Key not accepted on this endpoint; switch to session auth for the rest of the process.
        this.mode = "session";
        res = await this.send(path, opts);
      } else if (this.mode === "session" && this.hasSessionCreds) {
        this.cookie = undefined; // Session expired; log in again once.
        res = await this.send(path, opts);
      } else {
        throw new UnifiApiError(
          `${method} ${path} was rejected (HTTP ${res.status}). The API key is not accepted for this internal endpoint; ` +
            `set UNIFI_USERNAME and UNIFI_PASSWORD for a local admin account to enable it.`,
          res.status,
          method,
          path,
        );
      }
    }

    const env = (await HttpTransport.decode(res, method, path)) as LegacyEnvelope<T>;
    if (env?.meta?.rc === "error") {
      throw new UnifiApiError(`${method} ${path} failed: ${env.meta.msg ?? "unknown error"}`, res.status, method, path, env);
    }
    return env?.data ?? [];
  }

  /** All clients the controller has ever seen (including offline and blocked). */
  knownClients(): Promise<LegacyClient[]> {
    return this.request<LegacyClient>("/rest/user");
  }

  /** Currently connected clients with live stats. */
  activeClients(): Promise<LegacyClient[]> {
    return this.request<LegacyClient>("/stat/sta");
  }

  private stamgr(cmd: string, mac: string) {
    return this.request("/cmd/stamgr", { method: "POST", body: { cmd, mac: normalizeMac(mac) } });
  }

  block(mac: string) {
    return this.stamgr("block-sta", mac);
  }

  unblock(mac: string) {
    return this.stamgr("unblock-sta", mac);
  }

  /** Disconnect a client so it has to reconnect. */
  kick(mac: string) {
    return this.stamgr("kick-sta", mac);
  }

  /** Set the display name / note of a known client. */
  async setClientAlias(mac: string, name?: string, note?: string) {
    const client = (await this.knownClients()).find((c) => c.mac === normalizeMac(mac));
    if (!client?._id) throw new Error(`No known client with MAC ${mac}`);
    const body: Record<string, unknown> = {};
    if (name !== undefined) body.name = name;
    if (note !== undefined) {
      body.note = note;
      body.noted = note.length > 0;
    }
    return this.request(`/rest/user/${client._id}`, { method: "PUT", body });
  }
}

export function normalizeMac(mac: string): string {
  const hex = mac.toLowerCase().replace(/[^0-9a-f]/g, "");
  if (hex.length !== 12) throw new Error(`Invalid MAC address: ${mac}`);
  return hex.match(/../g)!.join(":");
}
