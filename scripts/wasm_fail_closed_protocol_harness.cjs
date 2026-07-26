const path = require("node:path");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function expectTypedRejection(name, operation, messageFragment) {
  let error;
  try {
    operation();
  } catch (caught) {
    error = caught;
  }

  assert(error, `${name} unexpectedly returned a value-capable result`);
  assert(
    error && typeof error === "object" && error.code === "CONXIAN_ERROR",
    `${name} did not preserve the typed WASM error object`,
  );
  assert(
    error.message.includes(messageFragment),
    `${name} returned an unexpected rejection: ${error.message}`,
  );
}

const [packageDirectory] = process.argv.slice(2);
if (!packageDirectory) {
  console.error(
    "usage: node scripts/wasm_fail_closed_protocol_harness.cjs <development-node-package>",
  );
  process.exit(2);
}

const api = require(path.resolve(packageDirectory));
assert(
  typeof api.ConclaveWasmClient.new_for_development === "function",
  "test-only development constructor is missing from the dedicated harness artifact",
);

const client = api.ConclaveWasmClient.new_for_development("http://127.0.0.1:9");
const accounts = client.accounts();
const cctp = client.cctp();
const testEvmAddress = `0x${"11".repeat(20)}`;
const cctpRecipient = `0x${testEvmAddress.slice(2).padStart(64, "0")}`;

try {
  expectTypedRejection(
    "accounts().prepare_execution",
    () =>
      accounts.prepare_execution([
        {
          target: testEvmAddress,
          value: "1",
          call_data: [0xa9, 0x05, 0x9c, 0xbb],
        },
      ]),
    "ERC-7579 execution requires a network-bound account, entry-point, and module registry",
  );

  expectTypedRejection(
    "cctp().prepare_burn_payload",
    () =>
      cctp.prepare_burn_payload({
        amount: 1_000_000n,
        source_chain: 0,
        destination_chain: 6,
        mint_recipient: cctpRecipient,
        burn_token: testEvmAddress,
      }),
    "CCTP burn encoding is disabled",
  );
} finally {
  cctp.free();
  accounts.free();
  client.free();
}

console.log("WASM_FAIL_CLOSED_PROTOCOL_ROUTES_OK checks=2");
