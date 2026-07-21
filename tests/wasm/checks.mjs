const RUNTIMES = ["browser", "node", "bundler", "worker"];

export function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function codeOf(error) {
  return error && typeof error === "object" ? error.code : undefined;
}

export function expectCode(action, expectedCode, label) {
  try {
    const result = action();
    throw new Error(`${label} unexpectedly succeeded: ${String(result)}`);
  } catch (error) {
    if (codeOf(error) !== expectedCode) {
      throw new Error(
        `${label} returned ${String(codeOf(error))}, expected ${expectedCode}: ${
          error?.message ?? String(error)
        }`,
      );
    }
    assert(
      typeof error?.message === "string" && error.message.startsWith(`${expectedCode}:`),
      `${label} did not preserve the stable error code in the message`,
    );
  }
}

export async function expectCodeAsync(action, expectedCode, label) {
  try {
    const result = await action();
    throw new Error(`${label} unexpectedly succeeded: ${String(result)}`);
  } catch (error) {
    if (codeOf(error) !== expectedCode) {
      throw new Error(
        `${label} returned ${String(codeOf(error))}, expected ${expectedCode}: ${
          error?.message ?? String(error)
        }`,
      );
    }
    assert(
      typeof error?.message === "string" && error.message.startsWith(`${expectedCode}:`),
      `${label} did not preserve the stable error code in the message`,
    );
  }
}

function assertNoSecretExports(api, lane) {
  const exportedNames = Object.keys(api);
  assert(
    !exportedNames.includes("derive_vutxo_key"),
    `${lane}: removed derive_vutxo_key export is present`,
  );
  assert(
    !exportedNames.includes("master_seed_hex"),
    `${lane}: seed export is present`,
  );
  assert(
    !exportedNames.some((name) => /private.?key|secret|seed/i.test(name)),
    `${lane}: secret-shaped export is present: ${exportedNames.join(", ")}`,
  );
  for (const [exportName, exportedValue] of Object.entries(api)) {
    if (typeof exportedValue !== "function" || !exportedValue.prototype) {
      continue;
    }
    const methodNames = Object.getOwnPropertyNames(exportedValue.prototype);
    assert(
      !methodNames.includes("derive_vutxo_key"),
      `${lane}: removed derive_vutxo_key method is present on ${exportName}`,
    );
    assert(
      !methodNames.includes("master_seed_hex"),
      `${lane}: seed method is present on ${exportName}`,
    );
    assert(
      !methodNames.some((name) => /private.?key|secret|seed/i.test(name)),
      `${lane}: secret-shaped method is present on ${exportName}: ${methodNames.join(", ")}`,
    );
  }
  assert(
    typeof api.ConclaveWasmClient === "function",
    `${lane}: ConclaveWasmClient is missing`,
  );
  assert(
    typeof api.WasmBitVm2Orchestrator === "function",
    `${lane}: WasmBitVm2Orchestrator is missing`,
  );
  assert(
    typeof api.WasmCovenantClient === "function",
    `${lane}: WasmCovenantClient is missing`,
  );
  assert(
    typeof api.WasmLightningClient === "function",
    `${lane}: WasmLightningClient is missing`,
  );
  assert(
    !("new_for_development" in api.ConclaveWasmClient),
    `${lane}: default artifact exposes ConclaveWasmClient.new_for_development`,
  );
  assert(
    !("new_for_development" in api.WasmBitVm2Orchestrator),
    `${lane}: default artifact exposes WasmBitVm2Orchestrator.new_for_development`,
  );
}

export async function runSurfaceChecks(api, lane) {
  assertNoSecretExports(api, lane);

  for (const runtime of RUNTIMES) {
    expectCode(
      () => api.ConclaveWasmClient.check_runtime_support(runtime),
      "UNSUPPORTED_RUNTIME",
      `${lane}: ${runtime} support check`,
    );
  }
  expectCode(
    () => api.ConclaveWasmClient.check_runtime_support("deno"),
    "UNSUPPORTED_RUNTIME",
    `${lane}: unknown runtime support check`,
  );

  // Provider-less construction fails before any object can look usable.
  expectCode(
    () => new api.ConclaveWasmClient("http://localhost"),
    "UNSUPPORTED_PROVIDER",
    `${lane}: default client construction`,
  );
  expectCode(
    () => new api.WasmBitVm2Orchestrator(),
    "UNSUPPORTED_PROVIDER",
    `${lane}: provider-less BitVM2 construction`,
  );
  expectCode(
    () => api.ConclaveWasmClient.new_with_provider("node", { privateKey: "must-not-be-read" }),
    "UNSUPPORTED_PROVIDER",
    `${lane}: unapproved provider construction`,
  );
  expectCode(
    () => api.ConclaveWasmClient.new_with_provider("unknown", {}),
    "UNSUPPORTED_RUNTIME",
    `${lane}: provider construction with unknown runtime`,
  );

  // Covenant construction is structural and does not require a provider. Its
  // malformed boundary inputs must use the typed INVALID_INPUT mapping.
  const covenants = new api.WasmCovenantClient();
  expectCode(
    () => covenants.generate_cat_vault_script("not-hex", "00".repeat(32)),
    "INVALID_INPUT",
    `${lane}: malformed covenant key encoding`,
  );
  expectCode(
    () => covenants.generate_cat_vault_script("00".repeat(31), "00".repeat(32)),
    "INVALID_INPUT",
    `${lane}: malformed covenant key length`,
  );
  expectCode(
    () => covenants.generate_cat_vault_script("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "00"),
    "INVALID_INPUT",
    `${lane}: malformed covenant hash length`,
  );
  expectCode(
    () => covenants.verify_recursive_invariant("not-an-array", "00".repeat(32)),
    "INVALID_INPUT",
    `${lane}: malformed covenant witness shape`,
  );

  // A valid structural covenant result contains only public script data.
  const covenant = covenants.generate_cat_vault_script(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "00".repeat(32),
  );
  const scriptHex = covenant.script_hex ?? covenant.scriptHex;
  const internalKey = covenant.internal_key ?? covenant.internalKey;
  assert(typeof scriptHex === "string", `${lane}: covenant script missing`);
  assert(typeof internalKey === "string", `${lane}: covenant key missing`);
  assert(!Object.keys(covenant).some((name) => /private|secret|seed/i.test(name)), `${lane}: secret-shaped covenant result`);

  // Lifecycle/state behavior is exercised without claiming payment support.
  // DLC state is an in-memory protocol state machine and does not require a
  // clock, network, wallet, or provider-backed payment implementation.
  const dlc = new api.WasmDlcClient();
  expectCode(
    () => dlc.accept_contract("not-json", ""),
    "INVALID_INPUT",
    `${lane}: malformed lifecycle contract`,
  );
  const offer = dlc.offer_contract("oracle", 1n, 2n);
  assert(offer.state === "Offered", `${lane}: initial DLC lifecycle state`);
  assert(
    !Object.keys(offer).some((name) => /private|secret|seed/i.test(name)),
    `${lane}: secret-shaped lifecycle result`,
  );

  return { lane, ok: true };
}
