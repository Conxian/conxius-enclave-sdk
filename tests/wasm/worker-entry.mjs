import init, * as api from "./.generated/web/conxius_enclave_sdk.js";
import { runSurfaceChecks } from "./checks.mjs";

try {
  await init();
  const result = await runSurfaceChecks(api, "worker");
  self.postMessage(result);
} catch (error) {
  self.postMessage({
    lane: "worker",
    ok: false,
    error: error?.message ?? String(error),
  });
}
