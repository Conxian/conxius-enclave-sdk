function assertCondition(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function errorCode(error) {
  return error && typeof error === "object" ? error.code : undefined;
}

function describeError(error) {
  return {
    code: errorCode(error) ?? null,
    message: error instanceof Error ? error.message : String(error),
  };
}

function expectTypedError(checks, name, operation, expectedCode) {
  let error;
  try {
    operation();
  } catch (caught) {
    error = caught;
  }

  assertCondition(error, `${name} unexpectedly succeeded`);
  assertCondition(
    errorCode(error) === expectedCode,
    `${name} returned ${JSON.stringify(describeError(error))}; expected ${expectedCode}`,
  );
  checks.push(name);
}

function buildValidLightningInvoice() {
  const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const data = [
    ...Array(7).fill(0),
    1,
    1,
    20,
    ...Array(52).fill(1),
    ...Array(104).fill(1),
  ];
  const hrp = "lnbc";
  let checksum = 1;
  for (const value of [
    ...[...hrp].map((character) => character.charCodeAt(0) >> 5),
    0,
    ...[...hrp].map((character) => character.charCodeAt(0) & 31),
    ...data,
    ...Array(6).fill(0),
  ]) {
    const top = checksum >> 25;
    checksum = ((checksum & 0x1ffffff) << 5) ^ value;
    for (let index = 0; index < generators.length; index += 1) {
      if ((top >> index) & 1) {
        checksum ^= generators[index];
      }
    }
  }
  checksum ^= 1;
  const checksumValues = Array.from(
    { length: 6 },
    (_, index) => (checksum >> (5 * (5 - index))) & 31,
  );
  return `${hrp}1${[...data, ...checksumValues].map((value) => charset[value]).join("")}`;
}

function publicSurfaceNames(api) {
  const names = new Set(Object.keys(api));
  for (const value of Object.values(api)) {
    if (typeof value === "function" && value.prototype) {
      for (const name of Object.getOwnPropertyNames(value.prototype)) {
        names.add(name);
      }
    }
  }
  return [...names].sort();
}

export function runBoundaryAssertions(api) {
  const checks = [];
  const exportedNames = publicSurfaceNames(api);
  const forbiddenSecretName =
    /derive_vutxo_key|master_seed_hex|private[_-]?key|signing[_-]?material|blinding[_-]?factors?|recovery[_-]?seed/i;

  assertCondition(
    typeof api.ConclaveWasmClient === "function",
    "generated artifact does not export ConclaveWasmClient",
  );
  assertCondition(
    typeof api.WasmBitVm2Orchestrator === "function",
    "generated artifact does not export WasmBitVm2Orchestrator",
  );
  assertCondition(
    typeof api.WasmLightningClient === "function",
    "generated artifact does not export WasmLightningClient",
  );
  assertCondition(
    typeof api.WasmLightningClientConstructor === "function",
    "generated artifact does not export WasmLightningClientConstructor",
  );
  assertCondition(
    !exportedNames.some((name) => forbiddenSecretName.test(name)),
    `forbidden secret-bearing public name found: ${exportedNames.join(", ")}`,
  );
  checks.push("generated API exposes no private-key, seed, or reversible-secret name");
  assertCondition(
    api.ConclaveWasmClient.new_for_development === undefined &&
      api.WasmBitVm2Orchestrator.new_for_development === undefined,
    "development simulator constructors leaked into the default artifact",
  );
  checks.push("development simulator constructors are absent from the default artifact");

  for (const runtime of ["browser", "node", "bundler", "worker"]) {
    expectTypedError(
      checks,
      `check_runtime_support(${runtime})`,
      () => api.ConclaveWasmClient.check_runtime_support(runtime),
      "UNSUPPORTED_RUNTIME",
    );
  }

  expectTypedError(
    checks,
    "check_runtime_support(unknown)",
    () => api.ConclaveWasmClient.check_runtime_support("unknown-runtime"),
    "UNSUPPORTED_RUNTIME",
  );
  expectTypedError(
    checks,
    "ConclaveWasmClient constructor",
    () => new api.ConclaveWasmClient("https://example.invalid"),
    "UNSUPPORTED_PROVIDER",
  );
  expectTypedError(
    checks,
    "ConclaveWasmClient.new_with_provider",
    () => api.ConclaveWasmClient.new_with_provider("node", {}),
    "UNSUPPORTED_PROVIDER",
  );
  expectTypedError(
    checks,
    "WasmBitVm2Orchestrator constructor",
    () => new api.WasmBitVm2Orchestrator(),
    "UNSUPPORTED_PROVIDER",
  );

  const validLightningPaymentHash = "11".repeat(32);
  const validLightningInvoice =
    "lnbc1qqqqqqqpp5ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppwdp039";
  const validLightningInvoiceFixture = buildValidLightningInvoice();

  expectTypedError(
    checks,
    "Lightning constructor malformed payment hash",
    () => new api.WasmLightningClient("payment-hash", validLightningInvoiceFixture, 1000n, null),
    "INVALID_INPUT",
  );
  expectTypedError(
    checks,
    "Lightning constructor malformed invoice",
    () => new api.WasmLightningClient(validLightningPaymentHash, "lnbc1-runtime-evidence", 1000n, null),
    "INVALID_INPUT",
  );
  expectTypedError(
    checks,
    "Lightning constructor malformed invoice structure",
    () => new api.WasmLightningClient(validLightningPaymentHash, validLightningInvoice, 1000n, null),
    "INVALID_INPUT",
  );
  expectTypedError(
    checks,
    "Lightning constructor zero amount",
    () => new api.WasmLightningClient(validLightningPaymentHash, validLightningInvoiceFixture, 0n, null),
    "INVALID_INPUT",
  );

  const lightningConstructor = new api.WasmLightningClientConstructor();
  expectTypedError(
    checks,
    "Lightning factory malformed payment hash",
    () => lightningConstructor.create_intent("payment-hash", validLightningInvoiceFixture, 1000n, null),
    "INVALID_INPUT",
  );
  lightningConstructor.free();

  const lightning = new api.WasmLightningClient(
    validLightningPaymentHash,
    validLightningInvoiceFixture,
    1000n,
    null,
  );
  assertCondition(lightning.get_status() === "Created", "Lightning client did not initialize");
  assertCondition(!lightning.can_retry(), "new Lightning client unexpectedly can retry");
  checks.push("Lightning initialization and initial lifecycle state");

  expectTypedError(
    checks,
    "Lightning malformed event",
    () => lightning.apply_event("{"),
    "INVALID_INPUT",
  );
  lightning.apply_event('"PaymentInitiated"');
  assertCondition(lightning.get_status() === "Pending", "Lightning initiation transition failed");
  lightning.apply_event('"PaymentInFlight"');
  assertCondition(lightning.get_status() === "Pending", "Lightning repeated pending transition failed");
  lightning.apply_event(
    '{"PaymentFailed":{"failure":"Transient","reason":"runtime evidence"}}',
  );
  assertCondition(lightning.get_status() === "Failed", "Lightning failure transition failed");
  assertCondition(lightning.can_retry(), "transient Lightning failure lost retry capability");
  lightning.apply_event('"PaymentRetried"');
  assertCondition(lightning.get_status() === "Pending", "Lightning retry transition failed");
  assertCondition(!lightning.can_retry(), "retried Lightning payment unexpectedly remains retryable");
  checks.push("Lightning malformed input, lifecycle, and repeated calls");

  const lightningProperties = Object.getOwnPropertyNames(lightning);
  assertCondition(
    !lightningProperties.some((name) => forbiddenSecretName.test(name)),
    `Lightning wrapper exposes a forbidden secret-bearing property: ${lightningProperties.join(", ")}`,
  );
  checks.push("Lightning wrapper has no secret readback property");

  const dlc = new api.WasmDlcClient();
  expectTypedError(
    checks,
    "DLC malformed contract",
    () => dlc.accept_contract("{", "remote-public-key"),
    "INVALID_INPUT",
  );
  dlc.free();
  lightning.free();
  checks.push("independent malformed-input client cleanup");

  return checks;
}
