import * as api from "./conxius_enclave_sdk.js";
import { runBoundaryAssertions } from "./boundary_assertions.mjs";

try {
  const wasmBytes = await (
    await fetch(new URL("./conxius_enclave_sdk_bg.wasm", import.meta.url))
  ).arrayBuffer();
  api.initSync(wasmBytes);
  const checks = runBoundaryAssertions(api);
  self.postMessage({ ok: true, checks: checks.length });
} catch (error) {
  self.postMessage({
    ok: false,
    message: error instanceof Error ? error.message : String(error),
  });
}
