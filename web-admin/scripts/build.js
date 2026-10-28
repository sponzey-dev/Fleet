import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const dist = join(root, "dist");

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });
copyFileSync(join(root, "index.html"), join(dist, "index.html"));
copyFileSync(join(root, "styles.css"), join(dist, "styles.css"));
copyFileSync(join(root, "app.js"), join(dist, "app.js"));
copyFileSync(join(root, "api-client.js"), join(dist, "api-client.js"));
copyFileSync(join(root, "admin-accounts.js"), join(dist, "admin-accounts.js"));
copyFileSync(join(root, "job-observer.js"), join(dist, "job-observer.js"));
copyFileSync(join(root, "job-output-reader.js"), join(dist, "job-output-reader.js"));
copyFileSync(join(root, "catalog-explorer.js"), join(dist, "catalog-explorer.js"));
copyFileSync(join(root, "catalog-actions.js"), join(dist, "catalog-actions.js"));
copyFileSync(join(root, "catalog-job.js"), join(dist, "catalog-job.js"));
copyFileSync(join(root, "api.schema.json"), join(dist, "api.schema.json"));

console.log("web-admin static export built");
