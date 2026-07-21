const { chromium } = require("playwright");

const [url, executablePath] = process.argv.slice(2);
if (!url || !executablePath) {
  console.error("usage: node scripts/wasm_runtime_browser.cjs <url> <chromium-path>");
  process.exit(2);
}

(async () => {
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
  });
  try {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: "load" });
    await page.waitForFunction(
      () => document.getElementById("runtime-marker")?.getAttribute("content") !== "pending",
      undefined,
      { timeout: 30_000 },
    );

    const marker = await page.locator("#runtime-marker").getAttribute("content");
    const title = await page.title();
    const result = await page.locator("#result").textContent();
    if (marker !== "ok" || title !== "WASM_RUNTIME_OK") {
      throw new Error(`browser marker=${marker ?? "missing"} title=${title}`);
    }
    console.log(`WASM_RUNTIME_OK mode=browser-and-web-worker result=${result?.trim() ?? ""}`);
  } finally {
    await browser.close();
  }
})().catch((error) => {
  console.error(`WASM_RUNTIME_FAILED mode=browser-and-web-worker: ${error.message}`);
  process.exit(1);
});
