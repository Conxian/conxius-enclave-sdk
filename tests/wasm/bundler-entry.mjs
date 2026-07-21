import init, * as api from "./.generated/web/conxius_enclave_sdk.js";
import { runSurfaceChecks } from "./checks.mjs";

window.__wasmResult = (async () => {
  await init();
  return runSurfaceChecks(api, "bundler");
})();
