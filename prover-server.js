const express = require("express");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const app = express();
app.use(express.json({ limit: "2mb" }));

// --- Config paths (adjust if needed) ---
const BUILD_DIR = path.join(__dirname, "build");
const WASM_PATH = path.join(BUILD_DIR, "withdraw_js", "withdraw.wasm");
const ZKEY_PATH = path.join(BUILD_DIR, "withdraw_final.zkey");
const VK_PATH = path.join(BUILD_DIR, "verification_key.json");

// --- Load verification key once at startup ---
let verificationKey = null;

try {
  const vkJson = fs.readFileSync(VK_PATH, "utf8");
  verificationKey = JSON.parse(vkJson);
  console.log("[ZKNON] Loaded verification key");
} catch (err) {
  console.error("[ZKNON] Failed to load verification key:", err.message);
  console.error("Make sure verification_key.json exists at:", VK_PATH);
}

// Helper to normalize input to string (snarkjs prefers strings / BigInts)
function toStringField(x) {
  if (typeof x === "string") return x;
  if (typeof x === "number") return x.toString();
  if (typeof x === "bigint") return x.toString();
  throw new Error("Invalid field type: " + typeof x);
}

function toStringArray(arr) {
  if (!Array.isArray(arr)) {
    throw new Error("Expected array");
  }
  return arr.map(toStringField);
}

// Simple health endpoint
app.get("/health", (req, res) => {
  const ok = !!verificationKey &&
    fs.existsSync(WASM_PATH) &&
    fs.existsSync(ZKEY_PATH);

  res.json({
    ok,
    hasVerificationKey: !!verificationKey,
    wasmPath: WASM_PATH,
    zkeyPath: ZKEY_PATH
  });
});

// Core endpoint: prove withdraw
app.post("/prove-withdraw", async (req, res) => {
  try {
    if (!verificationKey) {
      return res.status(500).json({ error: "Verification key not loaded on server" });
    }

    const {
      root,
      nullifier,
      amount,
      recipient,
      secret,
      idx,
      pathElements,
      pathIndex
    } = req.body || {};

    if (
      root === undefined ||
      nullifier === undefined ||
      amount === undefined ||
      recipient === undefined ||
      secret === undefined ||
      idx === undefined ||
      !Array.isArray(pathElements) ||
      !Array.isArray(pathIndex)
    ) {
      return res.status(400).json({
        error: "Missing required fields. Expected: root, nullifier, amount, recipient, secret, idx, pathElements[], pathIndex[]"
      });
    }

    const input = {
      root: toStringField(root),
      nullifier: toStringField(nullifier),
      amount: toStringField(amount),
      recipient: toStringField(recipient),
      secret: toStringField(secret),
      idx: toStringField(idx),
      pathElements: toStringArray(pathElements),
      pathIndex: toStringArray(pathIndex)
    };

    console.log("[ZKNON] Generating proof for withdraw request...");

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      WASM_PATH,
      ZKEY_PATH
    );

    // Optional self-check before returning proof
    const ok = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
    if (!ok) {
      console.error("[ZKNON] Self-verification of proof failed");
      return res.status(500).json({ error: "Proof self-verification failed" });
    }

    console.log("[ZKNON] Proof generated successfully");

    res.json({
      proof,
      publicSignals
    });
  } catch (err) {
    console.error("[ZKNON] Prover error:", err);
    res.status(500).json({ error: "Internal prover error" });
  }
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`[ZKNON] Prover server listening on port ${PORT}`);
});
