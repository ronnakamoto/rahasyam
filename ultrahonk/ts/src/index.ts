/**
 * nightfish-honk — browser/Node UltraHonk prover for the Nightfall client circuit.
 *
 * Reusable wrapper over `@noir-lang/noir_js` (witness solving) and
 * `@aztec/bb.js` (UltraHonk proving/verification compiled to WebAssembly). The
 * circuit is the `nightfish_honk_client_tx` Noir program proving the **full**
 * client statement (transfer / withdraw / swap), the UltraHonk analogue of
 * nf4's `unified_circuit.rs`. Its primitives are parity-verified against
 * Nightfall's `nf-curves` + `jf_primitives` (see `../rust` and
 * `../noir/src/tests.nr`).
 *
 * For multi-threaded browser proving, serve the page with COOP/COEP so
 * `SharedArrayBuffer` is available; otherwise pass `threads: 1`.
 */
import { Noir, type CompiledCircuit } from '@noir-lang/noir_js';
import { Barretenberg, BackendType, UltraHonkBackend } from '@aztec/bb.js';

/** A field element as a decimal/0x-hex string or a bigint. */
export type Field = string | bigint;

/** A Baby JubJub affine point. */
export interface Point {
  x: Field;
  y: Field;
}

/** One Merkle authentication-path element. */
export interface PathElement {
  sibling: Field;
  siblingOnLeft: boolean;
}

/**
 * The full client-statement witness, mirroring the Noir `StatementInputs`
 * struct field-for-field. `zkpPriv`/`zkpPrivLambda` are the witnessed reduction
 * of `Poseidon(rootKey, PRIVATE_KEY_PREFIX)` modulo the Baby JubJub subgroup
 * order (see the Rust reference `keys::zkp_private_key_witness`).
 *
 * `membershipProofs` carries one path per spent slot; each path must have the
 * deployed commitment-tree height (the reference vectors use 32).
 */
export interface StatementInputs {
  root: Field;
  rootKey: Field;
  zkpPriv: Field;
  zkpPrivLambda: Field;
  ephemeralKey: Field;
  feeTokenId: Field;
  fee: Field;
  nfAddress: Field;
  nfSlotId: Field;
  nullifiersValues: Field[]; // length 4
  nullifiersSalts: Field[]; // length 4
  publicKeys: Point[]; // length 4
  membershipProofs: PathElement[][]; // [4][depth]
  secretPreimages: Field[][]; // [4][3]
  commitmentsValues: Field[]; // length 2
  senderCommitmentSalts: Field[]; // length 3
  depositTokenIds: Field[]; // length 4
  depositSlotIds: Field[]; // length 4
  depositValues: Field[]; // length 4
  depositSecretHashes: Field[]; // length 4
  withdrawAddress: Field;
  partyAPublicKey: Point;
  partyBPublicKey: Point;
  nfTokenAId: Field;
  valueA: Field;
  nfTokenBId: Field;
  valueB: Field;
  swapNonce: Field;
  deadline: Field;
}

/** Number of framed public field outputs the circuit emits. */
export const NUM_PUBLIC_INPUTS = 27;

/**
 * Structured view of the framed 27-word public-input vector, matching nf4's
 * `From<&PublicInputs> for Vec<Fr254>`.
 */
export interface PublicOutputs {
  /** All 27 framed words, as 0x-hex strings (the raw circuit output). */
  raw: string[];
  fee: string;
  root: string;
  commitments: string[]; // 4
  nullifiers: string[]; // 4
  compressedSecrets: string[]; // 5
  swapLink: string;
  deadline: string;
  swapSide: string;
}

/** Result of {@link NightfishHonkProver.prove}. */
export interface ClientProof {
  proof: Uint8Array;
  /** The raw 27 framed public outputs as 0x-hex strings. */
  publicInputs: string[];
  outputs: PublicOutputs;
}

export interface ProverOptions {
  /** WASM threads. Defaults to 1 (universally safe). */
  threads?: number;
}

function toHexField(v: Field): string {
  const b = typeof v === 'bigint' ? v : BigInt(v);
  return '0x' + b.toString(16);
}

function pointAbi(p: Point) {
  return { x: toHexField(p.x), y: toHexField(p.y) };
}

function pathAbi(e: PathElement) {
  return { sibling: toHexField(e.sibling), sibling_on_left: e.siblingOnLeft };
}

/** Build the snake_case noir_js ABI object from a {@link StatementInputs}. */
export function toAbi(inputs: StatementInputs) {
  return {
    input: {
      root: toHexField(inputs.root),
      root_key: toHexField(inputs.rootKey),
      zkp_priv: toHexField(inputs.zkpPriv),
      zkp_priv_lambda: toHexField(inputs.zkpPrivLambda),
      ephemeral_key: toHexField(inputs.ephemeralKey),
      fee_token_id: toHexField(inputs.feeTokenId),
      fee: toHexField(inputs.fee),
      nf_address: toHexField(inputs.nfAddress),
      nf_slot_id: toHexField(inputs.nfSlotId),
      nullifiers_values: inputs.nullifiersValues.map(toHexField),
      nullifiers_salts: inputs.nullifiersSalts.map(toHexField),
      public_keys: inputs.publicKeys.map(pointAbi),
      membership_proofs: inputs.membershipProofs.map((path) => path.map(pathAbi)),
      secret_preimages: inputs.secretPreimages.map((sp) => sp.map(toHexField)),
      commitments_values: inputs.commitmentsValues.map(toHexField),
      sender_commitment_salts: inputs.senderCommitmentSalts.map(toHexField),
      deposit_token_ids: inputs.depositTokenIds.map(toHexField),
      deposit_slot_ids: inputs.depositSlotIds.map(toHexField),
      deposit_values: inputs.depositValues.map(toHexField),
      deposit_secret_hashes: inputs.depositSecretHashes.map(toHexField),
      withdraw_address: toHexField(inputs.withdrawAddress),
      party_a_public_key: pointAbi(inputs.partyAPublicKey),
      party_b_public_key: pointAbi(inputs.partyBPublicKey),
      nf_token_a_id: toHexField(inputs.nfTokenAId),
      value_a: toHexField(inputs.valueA),
      nf_token_b_id: toHexField(inputs.nfTokenBId),
      value_b: toHexField(inputs.valueB),
      swap_nonce: toHexField(inputs.swapNonce),
      deadline: toHexField(inputs.deadline),
    },
  };
}

/**
 * Decode the framed 27-word public-input vector. Layout (matching nf4):
 * `[framing, 1, fee, 1, root, 4, commitments[4], 4, nullifiers[4], 5,
 *   compressed_secrets[5], 1, swap_link, 1, deadline, 1, swap_side]`.
 */
export function decodeOutputs(raw: string[]): PublicOutputs {
  if (raw.length !== NUM_PUBLIC_INPUTS) {
    throw new Error(`expected ${NUM_PUBLIC_INPUTS} public outputs, got ${raw.length}`);
  }
  return {
    raw,
    fee: raw[2],
    root: raw[4],
    commitments: raw.slice(6, 10),
    nullifiers: raw.slice(11, 15),
    compressedSecrets: raw.slice(16, 21),
    swapLink: raw[22],
    deadline: raw[24],
    swapSide: raw[26],
  };
}

export class NightfishHonkProver {
  /** Number of framed public field outputs the circuit emits. */
  public readonly publicOutputCount = NUM_PUBLIC_INPUTS;

  private constructor(
    private readonly noir: Noir,
    private readonly api: Barretenberg,
    private readonly backend: UltraHonkBackend,
  ) {}

  /**
   * Initialise the prover from a compiled Noir circuit (the parsed
   * `circuits/client_tx/target/nightfish_honk_client_tx.json`).
   */
  static async create(
    circuit: CompiledCircuit,
    options: ProverOptions = {},
  ): Promise<NightfishHonkProver> {
    const threads = options.threads ?? 1;
    const noir = new Noir(circuit);
    const api = await Barretenberg.new({ backend: BackendType.Wasm, threads });
    const backend = new UltraHonkBackend(circuit.bytecode, api);
    return new NightfishHonkProver(noir, api, backend);
  }

  /** Solve the witness and generate an UltraHonk proof for `inputs`. */
  async prove(inputs: StatementInputs): Promise<ClientProof> {
    // Witness solving runs the circuit constraints; invalid inputs throw here
    // before any proving work happens (fail-closed).
    const { witness } = await this.noir.execute(toAbi(inputs));
    const { proof, publicInputs } = await this.backend.generateProof(witness);

    return {
      proof,
      publicInputs,
      outputs: decodeOutputs(publicInputs),
    };
  }

  /** Verify a proof produced by {@link prove}. */
  async verify(proof: ClientProof): Promise<boolean> {
    return this.backend.verifyProof({ proof: proof.proof, publicInputs: proof.publicInputs });
  }

  /** Release WASM resources. */
  async destroy(): Promise<void> {
    await this.api.destroy();
  }
}
