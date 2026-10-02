# unifi-mcp

An [MCP](https://modelcontextprotocol.io) server for UniFi Network. It lets Claude or another agent answer questions about your network ("what's connected to the IoT VLAN?", "which APs need firmware updates?") and make changes ("block that unknown Espressif device", "stop the cameras from reaching the internet").

Built and tested against the **UniFi Network 10.6.106** API with UniFi OS 5.x. It uses the zone-based firewall.

## How it talks to UniFi

| Capability | API used | Auth |
|---|---|---|
| Devices, networks, WiFi, firewall zones and policies, ordering, device restart, PoE power-cycle | Official Network API (`/proxy/network/integration/v1`) | API key |
| Client search including offline clients, block, unblock, reconnect, rename | Internal API (`/proxy/network/api/s/<site>`) | API key, falling back to local admin login |

The official API has no "block client" action, so blocking goes through the internal API. Some consoles accept the API key there and some don't. If yours doesn't, set `UNIFI_USERNAME`/`UNIFI_PASSWORD` and the server logs in with them automatically when the key is rejected.

The OpenAPI spec for 10.6.106 is in [`docs/`](docs/unifi-network-api-10.6.106.yaml).

## Setup

1. **Create an API key**: UniFi Network → Settings → Control Plane → Integrations → *Create API Key*.
2. **(Recommended) Create a local admin** for blocking: UniFi OS → Admins & Users → add an admin with *Restrict to local access only*, Network role *Site Admin*. Don't use your Ubiquiti cloud account; MFA will break login.
3. Build and check the connection:

```sh
npm install
npm run build
cp .env.example .env   # fill it in
set -a; source .env; set +a
npm run check
```

`npm run check` checks reachability, TLS, the API key, the site, firewall zones and internal-API access, and tells you what's missing.

## Run with Docker Compose

In Compose the server runs as a long-lived HTTP service (MCP Streamable HTTP at `/mcp`). Clients connect by URL with a bearer token.

```sh
cp .env.example .env        # fill in UNIFI_* and set MCP_AUTH_TOKEN:
openssl rand -hex 32        # → paste as MCP_AUTH_TOKEN
docker compose up -d --build
docker compose run --rm unifi-mcp dist/check.js   # connection check
docker compose logs -f
```

- The port is published on `127.0.0.1:3000` only. Set `MCP_PUBLISH` in `.env` to change it: `127.0.0.1:3100` for another local port, or `3000` to listen on every interface so other machines on the LAN can connect. If you expose it, put it behind a TLS reverse proxy. The token is the only thing standing between the network and your firewall.
- The server won't start in HTTP mode without an `MCP_AUTH_TOKEN` of at least 24 characters. Requests carrying a browser `Origin` header are rejected unless listed in `MCP_ALLOWED_ORIGINS`.
- The audit log is kept in the `unifi-mcp-data` volume (`/data/audit.log`). View it with `docker compose exec unifi-mcp cat /data/audit.log`.
- The container runs as a non-root user with a read-only filesystem and no Linux capabilities, and has a health check on `/healthz`.
- To verify the console's TLS certificate, mount it (see the commented volume in `compose.yaml`) and set `UNIFI_CA_CERT=/certs/unifi.pem`.

Connect clients to it:

**Claude Code**

```sh
claude mcp add --transport http unifi http://localhost:3000/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>"
```

**Claude Desktop** (via the `mcp-remote` bridge)

```json
{
  "mcpServers": {
    "unifi": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://localhost:3000/mcp", "--header", "Authorization:${AUTH}"],
      "env": { "AUTH": "Bearer <MCP_AUTH_TOKEN>" }
    }
  }
}
```

**Docker without a running service (stdio).** The client starts a throwaway container per session. No port or token is needed:

```json
{
  "mcpServers": {
    "unifi": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "--env-file", "/Users/regli/Github/Unifi-MCP/.env", "-e", "MCP_TRANSPORT=stdio", "unifi-mcp:latest"]
    }
  }
}
```

## Run directly with Node

### Use it from Claude

**Claude Code** (stdio)

```sh
claude mcp add unifi \
  -e UNIFI_HOST=https://192.168.1.1 \
  -e UNIFI_API_KEY=xxxx \
  -e UNIFI_USERNAME=mcp-admin -e UNIFI_PASSWORD=xxxx \
  -e UNIFI_VERIFY_TLS=false \
  -- node /Users/regli/Github/Unifi-MCP/dist/index.js
```

**Claude Desktop** (stdio, `~/Library/Application Support/Claude/claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "unifi": {
      "command": "node",
      "args": ["/Users/regli/Github/Unifi-MCP/dist/index.js"],
      "env": {
        "UNIFI_HOST": "https://192.168.1.1",
        "UNIFI_API_KEY": "xxxx",
        "UNIFI_USERNAME": "mcp-admin",
        "UNIFI_PASSWORD": "xxxx",
        "UNIFI_VERIFY_TLS": "false"
      }
    }
  }
}
```

## Tools

**Read**
- `unifi_get_overview`: version, site, device states, client count, WANs
- `unifi_list_devices`, `unifi_get_device`: devices with live stats
- `unifi_list_clients`: connected, all, or blocked clients, with `search` by name, vendor, IP or MAC
- `unifi_list_networks`, `unifi_list_wifi`
- `unifi_list_firewall_zones`, `unifi_list_firewall_policies`, `unifi_get_firewall_policy`, `unifi_get_firewall_policy_order`
- `unifi_api_get`: read-only access to any other endpoint

**Write** (not registered when `UNIFI_READ_ONLY=true`)
- `unifi_block_client`, `unifi_unblock_client`, `unifi_reconnect_client`, `unifi_rename_client`
- `unifi_create_firewall_policy`, `unifi_update_firewall_policy`, `unifi_set_firewall_policy_enabled`, `unifi_delete_firewall_policy`, `unifi_move_firewall_policy`
- `unifi_restart_device`, `unifi_power_cycle_port`

Firewall tools accept **zone and network names** ("IoT", "External") as well as IDs. Common rules can be described with simple fields: IPs/CIDRs/ranges, networks, MACs, domains, countries, ports and protocol. For anything else (apps, schedules, traffic-matching lists), pass `rawPolicy` in the API's own schema. `dryRun: true` shows the exact request without sending it.

### Example prompts

- "What's on my network right now that I don't recognise?"
- "Block the device called *ESP_3A1F2C* and note it as unknown."
- "Create a firewall policy so the IoT zone can't reach Internal, except my Home Assistant at 10.0.0.20 on port 8123. Show me a dry run first."
- "Block inbound traffic from CN and RU to my port-forwarded services."
- "Disable the 'Kids bedtime' policy."

## Safety

- Every change is appended to `~/.unifi-mcp/audit.log` (JSONL). Deleted policies are logged in full and can be restored with `rawPolicy`.
- System-defined policies are refused for update and delete.
- Write tools carry MCP `destructiveHint` annotations, so clients ask for approval.
- `UNIFI_READ_ONLY=true` leaves out every write tool.
- Policy order matters (first match wins per zone pair). Use `position: "top"` when a new BLOCK must beat an existing ALLOW.

## Configuration reference

All settings are environment variables; see [`.env.example`](.env.example). `MCP_TRANSPORT` is `stdio` (default when run with Node) or `http` (default in the Docker image), with `MCP_HOST`, `MCP_PORT`, `MCP_AUTH_TOKEN` and `MCP_ALLOWED_ORIGINS` applying to HTTP.

## Development

```sh
npm run dev        # run from source with tsx
npm test           # builder unit tests + end-to-end tests (stdio and HTTP) against a fake console
```
