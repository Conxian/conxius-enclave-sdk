import { createRequire } from "node:module";
import { isMainThread, parentPort, Worker, workerData } from "node:worker_threads";
import { pathToFileURL } from "node:url";
import path from "node:path";
import { runBoundaryAssertions } from "./wasm_runtime/boundary_assertions.mjs";

function serializeError(error) {
  return {
    code: error && typeof error === "object" ? error.code ?? null : null,
    message: error instanceof Error ? error.message : String(error),
  };
}

function loadNodePackage(packageDirectory) {
  const require = createRequire(path.join(packageDirectory, "package.json"));
  return require(packageDirectory);
}

async function runWorker(packageDirectory) {
  const result = await new Promise((resolve, reject) => {
    const worker = new Worker(new URL(import.meta.url), {
      type: "module",
      workerData: { packageDirectory },
    });
    worker.once("message", resolve);
    worker.once("error", reject);
    worker.once("exit", (code) => {
      if (code !== 0) {
        reject(new Error(`WASM Node worker exited with status ${code}`));
      }
    });
  });

  if (!result.ok) {
    throw new Error(result.message);
  }
  return result.checks;
}

if (!isMainThread) {
  try {
    const api = loadNodePackage(workerData.packageDirectory);
    const checks = runBoundaryAssertions(api);
    parentPort.postMessage({ ok: true, checks: checks.length });
  } catch (error) {
    parentPort.postMessage({ ok: false, message: serializeError(error).message });
    process.exitCode = 1;
  }
} else {
  const [mode, packageDirectory] = process.argv.slice(2);
  if (!mode || !packageDirectory || !["node", "bundler", "worker"].includes(mode)) {
    console.error("usage: node scripts/wasm_runtime_harness.mjs <node|bundler|worker> <package-dir>");
    process.exit(2);
  }

  try {
    let checkCount;
    if (mode === "node") {
      checkCount = runBoundaryAssertions(loadNodePackage(path.resolve(packageDirectory))).length;
    } else if (mode === "bundler") {
      const moduleUrl = pathToFileURL(
        path.join(path.resolve(packageDirectory), "conxius_enclave_sdk.js"),
      );
      const api = await import(moduleUrl.href);
      checkCount = runBoundaryAssertions(api).length;
    } else {
      checkCount = await runWorker(path.resolve(packageDirectory));
    }

    console.log(`WASM_RUNTIME_OK mode=${mode} checks=${checkCount}`);
  } catch (error) {
    const serialized = serializeError(error);
    console.error(`WASM_RUNTIME_FAILED mode=${mode} code=${serialized.code ?? "NONE"}`);
    console.error(serialized.message);
    process.exit(1);
  }
}
