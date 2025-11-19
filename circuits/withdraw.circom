pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

// Simple Merkle path verifier using Poseidon as hash
template MerklePath(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndex[depth]; // 0 or 1 bits

    signal output root;

    signal cur[depth + 1];
    cur[0] <== leaf;

    component hashers[depth];
    signal left[depth];
    signal right[depth];

    for (var i = 0; i < depth; i++) {
        hashers[i] = Poseidon(2);

        // if pathIndex[i] == 0, current is left child
        left[i]  <== (1 - pathIndex[i]) * cur[i] + pathIndex[i] * pathElements[i];
        right[i] <== pathIndex[i] * cur[i] + (1 - pathIndex[i]) * pathElements[i];

        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];

        cur[i + 1] <== hashers[i].out;
    }

    root <== cur[depth];
}

// ZKNON withdraw note circuit
template ZkNonWithdraw(depth) {
    // PUBLIC INPUTS
    signal input root;       // Merkle root
    signal input nullifier;  // Poseidon(secret, idx)
    signal input amount;     // note amount (field element)
    signal input recipient;  // recipient public key (field element)

    // PRIVATE INPUTS (witness)
    signal input secret;     // random secret
    signal input idx;        // leaf index (as field element)
    signal input pathElements[depth];
    signal input pathIndex[depth];

    // 1. commitment = Poseidon(secret, amount, idx)
    component hashNote = Poseidon(3);
    hashNote.inputs[0] <== secret;
    hashNote.inputs[1] <== amount;
    hashNote.inputs[2] <== idx;

    signal commitment;
    commitment <== hashNote.out;

    // 2. root must be a valid Merkle root for this commitment
    component merkle = MerklePath(depth);
    merkle.leaf <== commitment;
    for (var i = 0; i < depth; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndex[i]    <== pathIndex[i];
    }

    merkle.root === root;

    // 3. nullifier = Poseidon(secret, idx)
    component hashNull = Poseidon(2);
    hashNull.inputs[0] <== secret;
    hashNull.inputs[1] <== idx;

    hashNull.out === nullifier;

    // 4. Simple sanity check: amount must be non-zero
    amount !== 0;

    // Optional: you can add more constraints here, e.g.:
    // - amount <= MAX_AMOUNT
    // - recipient != 0
}

component main = ZkNonWithdraw(20);
