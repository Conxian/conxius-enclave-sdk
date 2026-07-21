import * as api from "./.generated/node/conxius_enclave_sdk.js";
import { runSurfaceChecks } from "./checks.mjs";

const result = await runSurfaceChecks(api, "node");
console.log(JSON.stringify(result));
