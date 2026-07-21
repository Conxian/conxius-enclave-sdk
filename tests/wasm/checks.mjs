const RUNTIMES = ["browser", "node", "bundler", "worker"];

export function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function codeOf(error) {
  return error && typeof error === "object" ? error.code : undefined;
}

export function expectCode(action, expectedCode, label, forbiddenFragments = []) {
  try {
    const result = action();
    assertNoSecretShapedResult(result, label);
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
    for (const fragment of forbiddenFragments) {
      assert(
        !error.message.includes(fragment),
        `${label} echoed rejected caller input ${JSON.stringify(fragment)}`,
      );
    }
  }
}

export async function expectCodeAsync(action, expectedCode, label) {
  try {
    const result = await action();
    assertNoSecretShapedResult(result, label);
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

function assertNoSecretShapedResult(result, label) {
  if (typeof result === "string") {
    assert(
      !/signature|aggregate|private.?key|secret|seed/i.test(result),
      `${label} returned a secret-shaped result`,
    );
    return;
  }
  if (result && typeof result === "object") {
    const resultNames = Object.keys(result);
    assert(
      !resultNames.some((name) => /signature|aggregate|private.?key|secret|seed/i.test(name)),
      `${label} returned secret-shaped fields: ${resultNames.join(", ")}`,
    );
  }
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

const VALID_LIGHTNING_PAYMENT_HASH =
  "0001020304050607080900010203040506070809000102030405060708090102";
const VALID_LIGHTNING_INVOICE =
  "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
const UPPERCASE_LIGHTNING_INVOICE = VALID_LIGHTNING_INVOICE.toUpperCase();
const MIXED_CASE_LIGHTNING_INVOICE = `L${VALID_LIGHTNING_INVOICE.slice(1)}`;
const INVALID_SIGNATURE_LIGHTNING_INVOICE =
  "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgqwgt7mcn5yqw3yx0w94pswkpq6j9uh6xfqqqtsk4tnarugeektd4hg5975x9am52rz4qskukxdmjemg92vvqz8nvmsye63r5ykel43pgz7zq0g2";
const IMPRECISE_AMOUNT_LIGHTNING_INVOICE =
  "lnbc2500000001p1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpusp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9qrsgq0lzc236j96a95uv0m3umg28gclm5lqxtqqwk32uuk4k6673k6n5kfvx3d2h8s295fad45fdhmusm8sjudfhlf6dcsxmfvkeywmjdkxcp99202x";

function encodeBech32(hrp, data) {
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
    for (let index = 0; index < BECH32_GENERATORS.length; index += 1) {
      if ((top >> index) & 1) {
        checksum ^= BECH32_GENERATORS[index];
      }
    }
  }
  checksum ^= 1;
  const checksumValues = Array.from(
    { length: 6 },
    (_, index) => (checksum >> (5 * (5 - index))) & 31,
  );
  return `${hrp}1${[...data, ...checksumValues]
    .map((value) => BECH32_CHARSET[value])
    .join("")}`;
}

function decodeBech32Data(invoice) {
  const separator = invoice.lastIndexOf("1");
  assert(separator > 0, "BOLT11 fixture is missing its Bech32 separator");
  const encoded = [...invoice.slice(separator + 1)].map((character) => {
    const value = BECH32_CHARSET.indexOf(character);
    assert(value >= 0, `BOLT11 fixture contains an invalid Bech32 character: ${character}`);
    return value;
  });
  return { hrp: invoice.slice(0, separator), data: encoded.slice(0, -6) };
}

function rewriteLightningInvoiceHrp(invoice, hrp) {
  return encodeBech32(hrp, decodeBech32Data(invoice).data);
}

function buildForgedLightningInvoice() {
  const data = [
    ...Array(7).fill(0),
    1,
    1,
    20,
    ...Array(52).fill(1),
    ...Array(104).fill(1),
  ];
  return encodeBech32("lnbc", data);
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
    typeof api.WasmLightningClientConstructor === "function",
    `${lane}: WasmLightningClientConstructor is missing`,
  );
  assert(
    typeof api.WasmArkClient === "function",
    `${lane}: direct WasmArkClient is missing`,
  );
  assert(
    typeof api.WasmBitVmClient === "function",
    `${lane}: direct WasmBitVmClient is missing`,
  );
  assert(
    typeof api.WasmDlcClient === "function",
    `${lane}: direct WasmDlcClient is missing`,
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

  const validLightningPaymentHash = VALID_LIGHTNING_PAYMENT_HASH;
  const validLightningInvoice = VALID_LIGHTNING_INVOICE;
  const uppercaseLightningInvoice = UPPERCASE_LIGHTNING_INVOICE;
  const mixedCaseLightningInvoice = MIXED_CASE_LIGHTNING_INVOICE;
  const forgedLightningInvoice = buildForgedLightningInvoice();
  const leadingZeroAmountInvoice = rewriteLightningInvoiceHrp(validLightningInvoice, "lnbc02500u");
  const malformedPaymentHash = "gg".repeat(32);
  const mismatchedPaymentHash = "ff".repeat(32);
  const validLightningAmount = 250_000_000n;

  expectCode(
    () => new api.WasmLightningClient("payment-hash", validLightningInvoice, 1000n, null),
    "INVALID_INPUT",
    `${lane}: Lightning malformed payment hash`,
    ["payment-hash"],
  );
  expectCode(
    () => new api.WasmLightningClient(malformedPaymentHash, validLightningInvoice, validLightningAmount, null),
    "INVALID_INPUT",
    `${lane}: Lightning non-hex payment hash`,
  );
  expectCode(
    () => new api.WasmLightningClient(validLightningPaymentHash, "lnbc1-runtime-evidence", 1000n, null),
    "INVALID_INPUT",
    `${lane}: Lightning malformed invoice`,
    ["lnbc1-runtime-evidence"],
  );
  expectCode(
    () => new api.WasmLightningClient(validLightningPaymentHash, validLightningInvoice, 0n, null),
    "INVALID_INPUT",
    `${lane}: Lightning zero amount`,
  );
  expectCode(
    () => new api.WasmLightningClient(validLightningPaymentHash, validLightningInvoice, 1000n, null),
    "INVALID_INPUT",
    `${lane}: Lightning invoice amount mismatch`,
  );
  expectCode(
    () => new api.WasmLightningClient(mismatchedPaymentHash, validLightningInvoice, validLightningAmount, null),
    "INVALID_INPUT",
    `${lane}: Lightning payment hash mismatch`,
    [mismatchedPaymentHash],
  );
  expectCode(
    () => new api.WasmLightningClient(validLightningPaymentHash, forgedLightningInvoice, validLightningAmount, null),
    "INVALID_INPUT",
    `${lane}: Lightning missing mandatory s/d/h fields`,
  );
  expectCode(
    () =>
      new api.WasmLightningClient(
        validLightningPaymentHash,
        INVALID_SIGNATURE_LIGHTNING_INVOICE,
        validLightningAmount,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning invalid signature`,
  );
  expectCode(
    () =>
      new api.WasmLightningClient(
        validLightningPaymentHash,
        mixedCaseLightningInvoice,
        validLightningAmount,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning mixed-case invoice`,
    [mixedCaseLightningInvoice],
  );
  expectCode(
    () =>
      new api.WasmLightningClient(
        validLightningPaymentHash,
        leadingZeroAmountInvoice,
        validLightningAmount,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning leading-zero HRP amount`,
  );
  expectCode(
    () => new api.WasmLightningClient(validLightningPaymentHash, "lnbc1p", validLightningAmount, null),
    "INVALID_INPUT",
    `${lane}: Lightning truncated pico HRP amount`,
  );
  expectCode(
    () =>
      new api.WasmLightningClient(
        validLightningPaymentHash,
        IMPRECISE_AMOUNT_LIGHTNING_INVOICE,
        validLightningAmount,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning imprecise pico amount`,
  );

  const lightningConstructor = new api.WasmLightningClientConstructor();
  expectCode(
    () => lightningConstructor.create_intent("payment-hash", validLightningInvoice, 1000n, null),
    "INVALID_INPUT",
    `${lane}: Lightning factory malformed payment hash`,
    ["payment-hash"],
  );
  expectCode(
    () =>
      lightningConstructor.create_intent(
        validLightningPaymentHash,
        "lnbc1-runtime-evidence",
        1000n,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning factory malformed invoice`,
    ["lnbc1-runtime-evidence"],
  );
  expectCode(
    () =>
      lightningConstructor.create_intent(
        validLightningPaymentHash,
        validLightningInvoice,
        0n,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning factory zero amount`,
  );
  expectCode(
    () =>
      lightningConstructor.create_intent(
        validLightningPaymentHash,
        forgedLightningInvoice,
        validLightningAmount,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning factory missing mandatory s/d/h fields`,
  );
  expectCode(
    () =>
      lightningConstructor.create_intent(
        validLightningPaymentHash,
        validLightningInvoice,
        1000n,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning factory invoice amount mismatch`,
  );

  const lightning = new api.WasmLightningClient(
    validLightningPaymentHash,
    validLightningInvoice,
    validLightningAmount,
    null,
  );
  assert(lightning.get_status() === "Created", `${lane}: valid Lightning construction`);
  assert(!lightning.can_retry(), `${lane}: new Lightning client unexpectedly can retry`);

  const uppercaseLightning = new api.WasmLightningClient(
    validLightningPaymentHash,
    uppercaseLightningInvoice,
    validLightningAmount,
    null,
  );
  assert(
    uppercaseLightning.get_status() === "Created",
    `${lane}: uppercase Lightning construction`,
  );
  assert(
    !uppercaseLightning.can_retry(),
    `${lane}: uppercase Lightning client unexpectedly can retry`,
  );

  const factoryLightning = lightningConstructor.create_intent(
    validLightningPaymentHash,
    validLightningInvoice,
    validLightningAmount,
    null,
  );
  assert(factoryLightning.get_status() === "Created", `${lane}: valid Lightning factory construction`);
  assert(!factoryLightning.can_retry(), `${lane}: valid Lightning factory unexpectedly can retry`);

  expectCode(
    () =>
      lightningConstructor.create_intent(
        validLightningPaymentHash,
        mixedCaseLightningInvoice,
        validLightningAmount,
        null,
      ),
    "INVALID_INPUT",
    `${lane}: Lightning factory mixed-case invoice`,
    [mixedCaseLightningInvoice],
  );
  const uppercaseFactoryLightning = lightningConstructor.create_intent(
    validLightningPaymentHash,
    uppercaseLightningInvoice,
    validLightningAmount,
    null,
  );
  assert(
    uppercaseFactoryLightning.get_status() === "Created",
    `${lane}: uppercase Lightning factory construction`,
  );
  assert(
    !uppercaseFactoryLightning.can_retry(),
    `${lane}: uppercase Lightning factory unexpectedly can retry`,
  );

  // These direct protocol clients are deliberately zero-state. They do not
  // construct or retain a provider-backed ConclaveWasmClient, enclave, URL,
  // key, or secret. Their valid-shaped value-bearing requests remain typed
  // unsupported, while malformed boundary data is rejected first.
  const ark = new api.WasmArkClient();
  const bitvm = new api.WasmBitVmClient();
  assertNoSecretShapedResult(ark, `${lane}: direct Ark client`);
  assertNoSecretShapedResult(bitvm, `${lane}: direct legacy BitVM client`);
  expectCode(
    () => ark.derive_vutxo_public_key(0),
    "PROTOCOL_UNSUPPORTED",
    `${lane}: Ark valid-shaped public-key derivation`,
  );
  expectCode(
    () => ark.sign_vutxo("00".repeat(32), 0),
    "PROTOCOL_UNSUPPORTED",
    `${lane}: Ark valid-shaped signing`,
  );
  expectCode(
    () => ark.sign_vutxo("00", 0),
    "INVALID_INPUT",
    `${lane}: Ark malformed signing digest`,
  );
  await expectCodeAsync(
    () => ark.recovery_scan(20, "https://asp.invalid"),
    "PROTOCOL_UNSUPPORTED",
    `${lane}: Ark async recovery scan`,
  );
  expectCode(
    () => bitvm.sign_challenge({ challenge_hash: "not-hex" }, "not-a-path", "not-a-key"),
    "PROTOCOL_UNSUPPORTED",
    `${lane}: legacy BitVM malformed signing request`,
  );
  expectCode(
    () =>
      bitvm.aggregate_challenge_signatures(
        ["not-hex"],
        ["not-hex"],
        ["not-hex"],
        { challenge_hash: "not-hex" },
      ),
    "PROTOCOL_UNSUPPORTED",
    `${lane}: legacy BitVM malformed aggregation request`,
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
  const accepted = dlc.accept_contract_value(offer, "remote_pubkey_hex");
  assert(accepted.state === "Accepted", `${lane}: Offered to Accepted lifecycle state`);
  assert(
    accepted.remote_pubkey === "remote_pubkey_hex",
    `${lane}: accepted lifecycle remote public key`,
  );
  assert(
    !Object.keys(accepted).some((name) => /private|secret|seed/i.test(name)),
    `${lane}: secret-shaped accepted lifecycle result`,
  );
  const acceptedState = accepted.state;
  const acceptedRemoteKey = accepted.remote_pubkey;
  expectCode(
    () => dlc.accept_contract_value(accepted, "second_remote_pubkey"),
    "CONXIAN_ERROR",
    `${lane}: repeated DLC acceptance transition`,
  );
  assert(accepted.state === acceptedState, `${lane}: invalid transition mutated state`);
  assert(
    accepted.remote_pubkey === acceptedRemoteKey,
    `${lane}: invalid transition mutated remote public key`,
  );

  return { lane, ok: true };
}
