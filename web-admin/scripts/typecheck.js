import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const schema = JSON.parse(readFileSync(join(root, "api.schema.json"), "utf8"));
const tsconfig = JSON.parse(readFileSync(join(root, "tsconfig.json"), "utf8"));
const { API_SCHEMA_VERSION, createApiClient } = await import(join(root, "api-client.js"));

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function pathArguments(path) {
  return [...path.matchAll(/\{([^}]+)\}/g)].map((match) => `${match[1]}-example`);
}

assert(tsconfig.compilerOptions.allowJs === true, "tsconfig must allow JavaScript checking");
assert(tsconfig.compilerOptions.checkJs === true, "tsconfig must enable checkJs");
assert(tsconfig.compilerOptions.noEmit === true, "tsconfig must be noEmit for static export");
assert(API_SCHEMA_VERSION === schema.schema_version, "API schema and client versions must match");
assert(Array.isArray(schema.endpoints), "API schema must define endpoint metadata");

const calls = [];
const client = createApiClient({
  tokenProvider: () => "typecheck-token",
  fetchImpl: async (path, options = {}) => {
    calls.push({ path, options });
    return {
      ok: true,
      status: 200,
      json: async () => ({ ok: true }),
    };
  },
});

for (const endpoint of schema.endpoints) {
  assert(endpoint.name && endpoint.method && endpoint.path, "endpoint metadata must be complete");
  assert(
    typeof client[endpoint.name] === "function",
    `API client must expose ${endpoint.name}`,
  );

  const args = pathArguments(endpoint.path);
  if (["POST", "PATCH"].includes(endpoint.method)) {
    args.push({});
  }
  await client[endpoint.name](...args);
}

for (const [index, endpoint] of schema.endpoints.entries()) {
  const call = calls[index];
  assert(call, `API client did not call ${endpoint.name}`);
  assert(!call.path.includes("{"), `${endpoint.name} must replace path parameters`);
  if (["public", "cookie"].includes(endpoint.authentication)) {
    assert(!Object.hasOwn(call.options.headers, "Authorization"), "cookie/public auth effects must not mix a bearer");
    assert(call.options.credentials === "same-origin" && call.options.cache === "no-store", "human auth effects must use private same-origin reads");
  } else {
    assert(call.options.headers.Authorization === "Bearer typecheck-token", "client must attach bearer token");
  }
  if (["POST", "PATCH"].includes(endpoint.method)) {
    assert(call.options.method === endpoint.method, `${endpoint.name} must use ${endpoint.method}`);
    assert(typeof call.options.body === "string", `${endpoint.name} must JSON encode request bodies`);
  } else if (endpoint.method === "DELETE") {
    assert(call.options.method === "DELETE", `${endpoint.name} must use DELETE`);
    assert(!call.options.body, `${endpoint.name} must not send a request body`);
  } else {
    assert(!call.options.method, `${endpoint.name} must use default GET`);
  }
}

console.log("web-admin API client type surface check passed");
