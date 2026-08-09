/* Copies the canonical landing page (../docs) into public/landing so the app
   serves it on its own origin at /landing/.

   docs/ stays the single source of truth - it's what GitHub Pages publishes.
   This copy is generated, gitignored, and refreshed automatically before every
   `npm run dev` and `npm run build`, so the two can never drift.
*/

import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../../docs");
const dest = resolve(here, "../public/landing");

if (!existsSync(src)) {
  console.warn(`[sync-landing] no docs/ at ${src} - skipping`);
  process.exit(0);
}

rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(src, dest, { recursive: true });

console.log("[sync-landing] docs/ -> public/landing/");
