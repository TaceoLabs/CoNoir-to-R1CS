use acir::native_types::WitnessStack;
use co_acvm::{Rep3AcvmType, solver::Rep3CoSolver};
use co_builder::flavours::ultra_flavour::UltraFlavour;
use co_noir::{
    AcirFormat, Bn254, CrsParser, HonkProof, Keccak256, Rep3CoUltraHonk, UltraHonk, VerifyingKey,
    VerifyingKeyBarretenberg,
};
use co_noir_types::Rep3Type;
use co_ultrahonk::prelude::{ProverCrs, ZeroKnowledge};
use eyre::Context;
use mpc_net::Network;
use noirc_artifacts::program::ProgramArtifact;
use std::{fs::File, path::Path, sync::Arc, time::Instant};

pub(crate) type F = ark_bn254::Fr;
type Curve = ark_bn254::G1Projective;
pub(crate) type Pairing = Bn254;
type CrsG2 = ark_bn254::G2Affine;
type Transcript = Keccak256;

const ZK: ZeroKnowledge = ZeroKnowledge::Yes;
const RECURSIVE: bool = false;
const HONK_RECURSION: bool = true;

pub fn get_program_artifact(circuit_path: impl AsRef<Path>) -> eyre::Result<ProgramArtifact> {
    let file = File::open(circuit_path).context("while opening program artifact file")?;
    let artifact =
        co_noir::program_artifact_from_reader(file).context("while parsing program artifact")?;
    Ok(artifact)
}

pub fn get_constraint_system_from_artifact(program_artifact: &ProgramArtifact) -> AcirFormat<F> {
    co_noir::get_constraint_system_from_artifact(program_artifact, HONK_RECURSION)
}

pub fn get_circuit_size(constraint_system: &AcirFormat<F>) -> eyre::Result<usize> {
    co_noir::compute_circuit_size::<Curve>(constraint_system, RECURSIVE)
}

pub fn get_prover_crs(
    crs_path: impl AsRef<Path>,
    circuit_size: usize,
) -> eyre::Result<Arc<ProverCrs<Curve>>> {
    Ok(CrsParser::<Curve>::get_crs_g1(crs_path, circuit_size, ZK)?.into())
}

pub fn get_verifier_crs(crs_path: impl AsRef<Path>) -> eyre::Result<CrsG2> {
    CrsParser::<Curve>::get_crs_g2::<Pairing>(crs_path)
}

pub fn generate_vk_barretenberg(
    constraint_system: &AcirFormat<F>,
    prover_crs: Arc<ProverCrs<Curve>>,
) -> eyre::Result<VerifyingKeyBarretenberg<Curve, UltraFlavour>> {
    co_noir::generate_vk_barretenberg::<Curve>(constraint_system, prover_crs, RECURSIVE)
}

pub fn get_vk(
    vk: VerifyingKeyBarretenberg<Curve, UltraFlavour>,
    verifier_crs: CrsG2,
) -> VerifyingKey<Pairing, UltraFlavour> {
    VerifyingKey::from_barrettenberg_and_crs(vk, verifier_crs)
}

pub fn conoir_witness_extension<N: Network>(
    inputs: Vec<Rep3AcvmType<F>>,
    compiled_program: ProgramArtifact,
    net0: &N,
    net1: &N,
) -> eyre::Result<WitnessStack<Rep3AcvmType<F>>> {
    tracing::info!("Starting CoNoir Witness extension...");
    let input_share = super::vec_to_witness_map(inputs);
    // init MPC protocol
    let rep3_vm = Rep3CoSolver::new_with_witness(net0, net1, compiled_program, input_share)
        .context("while creating VM")?;

    // execute witness generation in MPC
    let start = Instant::now();
    let (result_witness_share, _) = rep3_vm
        .solve_with_output()
        .context("while running witness generation")?;
    let duration_ms = start.elapsed().as_micros() as f64 / 1000.;
    tracing::info!("Extending witness took {duration_ms} ms");
    Ok(result_witness_share)
}

pub fn r1cs_witness_extension_with_helper<N: Network>(
    inputs: Vec<Rep3AcvmType<F>>,
    traces: Vec<Vec<Rep3AcvmType<F>>>,
    compiled_program: ProgramArtifact,
    net0: &N,
    net1: &N,
) -> eyre::Result<WitnessStack<Rep3AcvmType<F>>> {
    tracing::info!("Starting R1CS Witness extension...");
    let input_share = super::vec_to_witness_map(inputs);
    // init MPC protocol
    let rep3_vm = Rep3CoSolver::new_with_witness(net0, net1, compiled_program, input_share)
        .context("while creating VM")?;

    // execute witness generation in MPC
    let start = Instant::now();
    let result_witness_share = rep3_vm
        .solve_r1cs_with_helper(traces)
        .context("while running witness generation")?;
    let duration_ms = start.elapsed().as_micros() as f64 / 1000.;
    tracing::info!("Extending witness took {duration_ms} ms");
    Ok(result_witness_share)
}

pub fn prove<N: Network>(
    constraint_system: &AcirFormat<F>,
    witness: Vec<Rep3Type<F>>,
    prover_crs: &ProverCrs<Curve>,
    net0: &N,
    net1: &N,
) -> eyre::Result<(HonkProof<F>, Vec<F>)> {
    tracing::info!("Starting proving key generation...");
    let start = Instant::now();
    let proving_key =
        co_noir::generate_proving_key_rep3(constraint_system, witness, RECURSIVE, net0, net1)?;
    let duration_ms = start.elapsed().as_micros() as f64 / 1000.;
    tracing::info!("Build proving key took {duration_ms} ms");

    // execute prover in MPC
    let start = Instant::now();
    let (proof, public_inputs) =
        Rep3CoUltraHonk::<_, Transcript, UltraFlavour>::prove(net0, proving_key, prover_crs, ZK)?;
    let duration_ms = start.elapsed().as_micros() as f64 / 1000.;
    tracing::info!("Generate proof took {duration_ms} ms");
    Ok((proof, public_inputs))
}

pub fn verify(
    proof: HonkProof<F>,
    public_inputs: &[F],
    verifying_key: &VerifyingKey<Pairing, UltraFlavour>,
) -> eyre::Result<bool> {
    UltraHonk::<_, Transcript, UltraFlavour>::verify(proof, public_inputs, verifying_key, ZK)
        .context("while verifying proof")
}
