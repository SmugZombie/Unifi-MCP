import assert from "node:assert/strict";
import { test } from "node:test";
import { safeJoin } from "../src/http.ts";

const P = "/proxy/network/api/s/default";

test("safeJoin allows normal paths and query strings", () => {
  assert.equal(safeJoin(P, "/stat/sta"), `${P}/stat/sta`);
  assert.equal(safeJoin(P, "/rest/user/abc123"), `${P}/rest/user/abc123`);
  assert.equal(safeJoin(P, "/traffic-flow-latest-statistics?period=DAY&top=5"), `${P}/traffic-flow-latest-statistics?period=DAY&top=5`);
  // Dots inside a segment (versions, file names) are fine.
  assert.equal(safeJoin(P, "/v1.2/x..y/.hidden"), `${P}/v1.2/x..y/.hidden`);
  // ".." inside the query string is not a path segment.
  assert.equal(safeJoin(P, "/search?q=../etc"), `${P}/search?q=../etc`);
});

test("safeJoin rejects every way out of the prefix", () => {
  for (const bad of [
    "/../../../v2/api/site/default/clients/active",
    "/stat/../../../../api/users",
    "/./stat",
    "/%2e%2e/%2e%2e/api/users",
    "/%2E%2E/x",
    "/.%2e/x",
    "/stat%2f..%2f..%2fapi",
    "/stat\\..\\..\\api",
    "/stat#/../../api",
    "/%zz",
    "stat/sta",
    "/..",
  ]) {
    assert.throws(() => safeJoin(P, bad), /Invalid API path/, bad);
  }
});

test("safeJoin rejects a prefix that itself escapes", () => {
  assert.throws(() => safeJoin("/proxy/network/api/s/../../evil", "/x"), /resolves outside/);
});
