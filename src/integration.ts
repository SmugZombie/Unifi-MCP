import { HttpTransport, UnifiApiError, type RequestOptions } from "./http.js";

/** Paged response envelope used by every list endpoint of the official API. */
interface Page<T> {
  offset: number;
  limit: number;
  count: number;
  totalCount: number;
  data: T[];
}

export interface Site {
  id: string;
  internalReference: string;
  name: string;
}

const PAGE_SIZE = 200;

/**
 * Client for the official UniFi Network Integration API
 * (https://<console>/proxy/network/integration/v1), authenticated with an API key.
 */
export class IntegrationClient {
  private site?: Site;

  constructor(
    private readonly http: HttpTransport,
    private readonly apiKey: string | undefined,
    private readonly siteSelector: string,
  ) {}

  get available(): boolean {
    return Boolean(this.apiKey);
  }

  async request<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
    if (!this.apiKey) {
      throw new Error("This tool needs the official UniFi API: set UNIFI_API_KEY.");
    }
    const fullPath = `/proxy/network/integration${path}`;
    const method = opts.method ?? "GET";
    const res = await this.http.raw(fullPath, { ...opts, headers: { ...opts.headers, "X-API-KEY": this.apiKey } });
    return (await HttpTransport.decode(res, method, fullPath)) as T;
  }

  /** Fetch every page of a list endpoint. */
  async listAll<T>(path: string, filter?: string, max = 5000): Promise<T[]> {
    const items: T[] = [];
    for (let offset = 0; offset < max; offset += PAGE_SIZE) {
      const page = await this.request<Page<T>>(path, { query: { offset, limit: PAGE_SIZE, filter } });
      items.push(...page.data);
      if (page.data.length === 0 || items.length >= page.totalCount) break;
    }
    return items;
  }

  async resolveSite(): Promise<Site> {
    if (this.site) return this.site;
    const sites = await this.listAll<Site>("/v1/sites");
    const sel = this.siteSelector.toLowerCase();
    const site =
      sites.find((s) => s.id === this.siteSelector) ??
      sites.find((s) => s.internalReference.toLowerCase() === sel) ??
      sites.find((s) => s.name.toLowerCase() === sel) ??
      (sites.length === 1 ? sites[0] : undefined);
    if (!site) {
      throw new Error(
        `Site "${this.siteSelector}" not found. Available: ${sites.map((s) => `${s.name} (${s.internalReference})`).join(", ")}`,
      );
    }
    this.site = site;
    return site;
  }

  /** Request a path under /v1/sites/{siteId}. */
  async siteRequest<T = unknown>(subPath: string, opts: RequestOptions = {}): Promise<T> {
    const site = await this.resolveSite();
    return this.request<T>(`/v1/sites/${site.id}${subPath}`, opts);
  }

  async siteList<T>(subPath: string, filter?: string): Promise<T[]> {
    const site = await this.resolveSite();
    return this.listAll<T>(`/v1/sites/${site.id}${subPath}`, filter);
  }

  static isNotFound(err: unknown): boolean {
    return err instanceof UnifiApiError && err.status === 404;
  }
}
