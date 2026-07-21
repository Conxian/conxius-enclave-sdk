import { createReadStream } from "node:fs";
import { existsSync, promises as fs } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";
import { chromium } from "playwright";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)));

function mimeType(pathname) {
  switch (extname(pathname)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
    case ".mjs":
      return "text/javascript; charset=utf-8";
    case ".wasm":
      return "application/wasm";
    case ".json":
      return "application/json; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}

function startStaticServer() {
  const server = createServer(async (request, response) => {
    try {
      const requestPath = decodeURIComponent((request.url ?? "/").split("?")[0]);
      const candidate = resolve(join(root, `.${requestPath}`));
      const rootRelative = relative(root, candidate);
      if (rootRelative.startsWith("..") || rootRelative.includes("\0")) {
        response.writeHead(403).end();
        return;
      }
      const pathname = normalize(candidate === root ? join(root, "browser.html") : candidate);
      if (!existsSync(pathname)) {
        response.writeHead(404).end(`Not found: ${requestPath}`);
        return;
      }
      response.writeHead(200, { "content-type": mimeType(pathname) });
      createReadStream(pathname).pipe(response);
    } catch (error) {
      response.writeHead(500).end(error?.message ?? String(error));
    }
  });
  return new Promise((resolveServer) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolveServer({ server, origin: `http://127.0.0.1:${address.port}` });
    });
  });
}

async function runBrowserPage(browser, url, resultExpression, label) {
  const page = await browser.newPage();
  page.on("pageerror", (error) => {
    console.error(`${label} page error: ${error.message}`);
  });
  await page.goto(url, { waitUntil: "networkidle" });
  const result = await page.evaluate(async (expression) => {
    await new Promise((resolve) => setTimeout(resolve, 0));
    return await (0, eval)(expression);
  }, resultExpression);
  if (!result?.ok) {
    throw new Error(`${label} failed: ${result?.error ?? JSON.stringify(result)}`);
  }
  console.log(JSON.stringify(result));
  await page.close();
}

await fs.mkdir(join(root, ".generated/bundler"), { recursive: true });
await fs.copyFile(
  join(root, ".generated/web/conxius_enclave_sdk_bg.wasm"),
  join(root, ".generated/bundler/conxius_enclave_sdk_bg.wasm"),
);

await build({
  entryPoints: [join(root, "bundler-entry.mjs")],
  bundle: true,
  format: "esm",
  platform: "browser",
  outfile: join(root, ".generated/bundler/bundle.mjs"),
  loader: { ".wasm": "file" },
  assetNames: "bundled-[name]-[hash]",
  logLevel: "warning",
});

const { server, origin } = await startStaticServer();
const browser = await chromium.launch({ headless: true });
try {
  await runBrowserPage(browser, `${origin}/browser.html`, "window.__wasmResult", "browser");
  await runBrowserPage(browser, `${origin}/worker.html`, "window.__workerResult", "worker");
  await runBrowserPage(browser, `${origin}/bundler.html`, "window.__wasmResult", "bundler");
} finally {
  await browser.close();
  server.close();
  await fs.rm(join(root, ".generated/bundler/bundle.mjs"), { force: true });
}

const nodeProcess = await import("node:child_process").then(({ execFile }) =>
  new Promise((resolveProcess, rejectProcess) => {
    execFile(process.execPath, [join(root, "node.mjs")], { cwd: root }, (error, stdout, stderr) => {
      if (error) {
        rejectProcess(new Error(`node lane failed: ${stderr || error.message}`));
        return;
      }
      process.stdout.write(stdout);
      resolveProcess();
    });
  }),
);
void nodeProcess;

console.log("WASM runtime evidence passed: node, browser, worker, bundler");
