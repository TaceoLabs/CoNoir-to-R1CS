use crate::{
    noir::ultrahonk::{self, Curve, F},
    r1cs::noir_proof_schema::{self, NoirProofScheme},
};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use co_circom::Rep3SharedWitness;
use co_groth16::{LibSnarkReduction, Rep3CoGroth16};
use eyre::Context;
use mpc_core::protocols::rep3::{self, Rep3State, conversion::A2BType, id::PartyID};
use mpc_net::Network;
use noirc_artifacts::program::ProgramArtifact;
use rand::{CryptoRng, Rng};
use std::time::Instant;

fn translate_witness_to_r1cs<N: Network>(
    witness: Vec<Rep3AcvmType<F>>,
    proof_schema: &NoirProofScheme<F>,
    net0: &N,
    net1: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3AcvmType<F>>> {
    let witness_map = ultrahonk::vec_to_witness_map(witness);

    let mut driver = Rep3AcvmSolver::new(net0, net1, A2BType::default())?;

    let partial_witness = proof_schema.r1cs.solve_witness_vec_rep3(
        &proof_schema.witness_builders,
        &witness_map,
        &mut driver,
    )?;
    let mut r1cs = noir_proof_schema::fill_witness_rep3(partial_witness, rep3_state)
        .context("while filling witness")?;

    proof_schema.reorder_witness_for_public_inputs(&mut r1cs);
    Ok(r1cs)
}

pub fn trace_to_r1cs_witness<N: Network>(
    inputs: Vec<Rep3AcvmType<F>>,
    traces: Vec<Vec<Rep3AcvmType<F>>>,
    proof_schema: &NoirProofScheme<F>,
    net0: &N,
    net1: &N,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3AcvmType<F>>> {
    let witness = ultrahonk::r1cs_witness_extension_with_helper(
        inputs,
        traces,
        proof_schema.program.to_owned(),
        net0,
        net1,
    )?;

    translate_witness_to_r1cs(witness, proof_schema, net0, net1, rep3_state)
}

pub fn r1cs_witness_to_cogroth16(
    proof_schema: &NoirProofScheme<F>,
    witness: Vec<Rep3AcvmType<F>>,
    id: PartyID,
) -> Rep3SharedWitness<F> {
    let public_size = proof_schema.public_input_indices.len() + 1;
    let shared_size = proof_schema.r1cs.num_witnesses() - public_size;
    let mut public_inputs = Vec::with_capacity(public_size);
    let mut shared_inputs = Vec::with_capacity(shared_size);

    for w in witness.iter().take(public_size) {
        match w {
            Rep3AcvmType::Public(value) => {
                public_inputs.push(*value);
            }
            _ => {
                panic!("Expected public input, found shared input");
            }
        }
    }

    for w in witness.into_iter().skip(public_size) {
        match w {
            Rep3AcvmType::Public(value) => {
                shared_inputs.push(rep3::arithmetic::promote_to_trivial_share(id, value));
            }
            Rep3AcvmType::Shared(value) => {
                shared_inputs.push(value);
            }
        }
    }

    assert_eq!(
        public_inputs.len(),
        public_size,
        "Public inputs size mismatch"
    );
    assert_eq!(
        shared_inputs.len(),
        shared_size,
        "Shared inputs size mismatch"
    );

    Rep3SharedWitness {
        public_inputs,
        witness: shared_inputs,
    }
}

pub fn setup_r1cs<R: Rng + CryptoRng>(
    compiled_program: ProgramArtifact,
    rng: &mut R,
) -> eyre::Result<(NoirProofScheme<F>, ProvingKey<Curve>, ConstraintMatrices<F>)> {
    let mut proof_schema = NoirProofScheme::<F>::from_program(compiled_program)
        .context("while creating Noir proof schema")?;
    proof_schema.reorder_for_public_inputs();

    // Generate the Groth16 proving key
    let pk = proof_schema
        .r1cs
        .generate_proving_key::<ark_bn254::Bn254, _>(rng)
        .context("While generating proving key")?;
    let cs = proof_schema.r1cs.to_ark_constraint_matrix();

    Ok((proof_schema, pk, cs))
}

pub fn prove<N: Network>(
    constraint_system: &ConstraintMatrices<F>,
    proving_key: &ProvingKey<Curve>,
    witness: Rep3SharedWitness<F>,
    net0: &N,
    net1: &N,
) -> eyre::Result<(Proof<Curve>, Vec<F>)> {
    let public_input = witness.public_inputs[1..].to_vec(); // Skip the constant 1

    let start = Instant::now();
    let proof = Rep3CoGroth16::prove::<N, LibSnarkReduction>(
        net0,
        net1,
        proving_key,
        constraint_system,
        witness,
    )?;

    let duration_ms = start.elapsed().as_micros() as f64 / 1000.;
    tracing::info!("Generate proof took {duration_ms} ms");

    Ok((proof, public_input))
}

pub fn verify(
    vk: &VerifyingKey<Curve>,
    proof: &Proof<Curve>,
    public_inputs: &[F],
) -> eyre::Result<bool> {
    let vk = ark_groth16::prepare_verifying_key(vk);
    let proof_valid = ark_groth16::Groth16::<Curve>::verify_proof(&vk, proof, public_inputs)
        .map_err(eyre::Report::from)?;
    Ok(proof_valid)
}
