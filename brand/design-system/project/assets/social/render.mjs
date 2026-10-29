// backtide · renders the social preview (social.html) to ../social.png, 1280 x 640, in a headless
// Chrome of its own over CDP (scripts/demo-video/cdp.mjs: Node's built-in WebSocket, no npm).
//
//   node brand/design-system/project/assets/social/render.mjs [--out file.png]
//
// It serves the design system's folder on 127.0.0.1 (read only) so the page loads its own fonts
// under its strict CSP, waits for Lora and DM Sans, and stops without writing if a font is
// missing, the mark is not components/Wordmark/mark.html, anything leaves the 40px safe area,
// the page logs an error, or the PNG is 1 MB or more.
import { createReadStream, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { connect, launch } from "../../../../../scripts/demo-video/cdp.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SYSTEM = resolve(HERE, "../.."); // brand/design-system/project
const WIDTH = 1280;
const HEIGHT = 640;
const SAFE = 40; // GitHub's safe area: keep everything this far from every edge
const LIMIT = 1024 * 1024; // GitHub takes up to 1 MB

const args = process.argv.slice(2);
const at = args.indexOf("--out");
const out = at >= 0 ? resolve(args[at + 1]) : resolve(HERE, "../social.png");

// The mark must be the Wordmark's, character for character.
const mark = readFileSync(resolve(SYSTEM, "components/Wordmark/mark.html"), "utf8").trim();
if (!readFileSync(resolve(HERE, "social.html"), "utf8").includes(mark)) {
  console.error("social.html: the mark is not components/Wordmark/mark.html; copy it again");
  process.exit(1);
}

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2",
  ".svg": "image/svg+xml",
};
function serve() {
  const server = createServer((req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
    const file = resolve(SYSTEM, "." + path);
    const inside = file.startsWith(SYSTEM + sep);
    if (req.method !== "GET" || !inside || !existsSync(file) || !statSync(file).isFile()) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream" });
    createReadStream(file).pipe(res);
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

const server = await serve();
const origin = `http://127.0.0.1:${server.address().port}`;
const chrome = await launch({ port: 9500 + Math.floor(Math.random() * 200), width: WIDTH, height: HEIGHT });
const page = await connect(chrome.pageUrl);
const problems = [];
page.on("Runtime.exceptionThrown", (e) => problems.push(e.exceptionDetails.text));
page.on("Log.entryAdded", ({ entry }) => entry.level === "error" && problems.push(`${entry.text} ${entry.url || ""}`));

let code = 0;
try {
  await page.send("Page.enable");
  await page.send("Runtime.enable");
  await page.send("Log.enable");
  await page.send("Emulation.setDeviceMetricsOverride", { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false });
  const loaded = page.once("Page.loadEventFired");
  await page.send("Page.navigate", { url: `${origin}/assets/social/social.html` });
  await loaded;

  const fonts = await page.evaluate(`(async () => {
    const want = ['400 92px Lora', '500 52px "DM Sans"', '400 34px "DM Sans"'];
    const got = await Promise.all(want.map((f) => document.fonts.load(f)));
    await document.fonts.ready;
    return got.every((faces) => faces.length && faces.every((f) => f.status === "loaded"));
  })()`);
  if (!fonts) throw new Error("Lora or DM Sans did not load");

  const outside = await page.evaluate(`(() => {
    const bad = [];
    for (const el of document.querySelectorAll(".social > *, .social svg")) {
      const r = el.getBoundingClientRect();
      if (r.left < ${SAFE} || r.top < ${SAFE} || r.right > ${WIDTH - SAFE} || r.bottom > ${HEIGHT - SAFE})
        bad.push(el.className.baseVal ?? el.className);
    }
    return bad;
  })()`);
  if (outside.length) throw new Error(`outside the ${SAFE}px safe area: ${outside.join(", ")}`);

  const { data } = await page.send("Page.captureScreenshot", {
    format: "png",
    clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT, scale: 1 },
  });
  if (problems.length) throw new Error(`the page logged errors:\n${problems.join("\n")}`);
  const png = Buffer.from(data, "base64");
  if (png.length >= LIMIT) throw new Error(`${png.length} bytes: GitHub takes under 1 MB`);
  writeFileSync(out, png);
  console.log(`${out} · ${WIDTH} x ${HEIGHT} · ${png.length} bytes`);
} catch (error) {
  console.error(error.message);
  code = 1;
} finally {
  page.close();
  chrome.stop();
  server.close();
}
process.exit(code);
