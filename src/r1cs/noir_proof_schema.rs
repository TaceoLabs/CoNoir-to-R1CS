use {
    crate::r1cs::{noir_to_r1cs::noir_to_r1cs, r1cs::R1CS, r1cs_solver::WitnessBuilder},
    ark_ff::PrimeField,
    co_acvm::Rep3AcvmType,
    eyre::ensure,
    mpc_core::protocols::rep3::{self, Rep3State},
    noirc_artifacts::program::ProgramArtifact,
    rand::Rng,
    serde::{Deserialize, Serialize},
    std::num::NonZero,
    tracing::{info, instrument},
};

/// A scheme for proving a Noir program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoirProofScheme<F: PrimeField> {
    pub program: ProgramArtifact,
    pub r1cs: R1CS<F>,
    pub witness_builders: Vec<WitnessBuilder<F>>,
    pub public_input_indices: Vec<NonZero<u32>>, // Does not include the index 0
}

impl<F: PrimeField> NoirProofScheme<F> {
    #[instrument(skip_all)]
    pub fn from_program(program: ProgramArtifact) -> eyre::Result<Self> {
        info!("Program noir version: {}", program.noir_version);
        // info!("Program entry point: fn main{};", PrintAbi(&program.abi));
        ensure!(
            program.bytecode.functions.len() == 1,
            "Program must have one entry point."
        );

        // Extract bits from Program Artifact.
        let main = &program.bytecode.functions[0];
        info!(
            "ACIR: {} witnesses, {} opcodes.",
            main.current_witness_index,
            main.opcodes.len()
        );

        // Compile to R1CS schemes
        let (r1cs, witness_map, witness_builders, public_inputs) = noir_to_r1cs(main)?;
        info!(
            "R1CS {} constraints, {} witnesses, A {} entries, B {} entries, C {} entries",
            r1cs.num_constraints(),
            r1cs.num_witnesses(),
            r1cs.a.num_entries(),
            r1cs.b.num_entries(),
            r1cs.c.num_entries()
        );

        // Translate the public inputs with the witness map.
        let mut public_input_indices = Vec::with_capacity(public_inputs.len());
        for p in public_inputs {
            let index = witness_map[p as usize].expect("Must be there");
            public_input_indices.push(index);
        }

        Ok(Self {
            program,
            r1cs,
            witness_builders,
            public_input_indices,
        })
    }

    #[must_use]
    pub const fn size(&self) -> (usize, usize) {
        (self.r1cs.num_constraints(), self.r1cs.num_witnesses())
    }

    /// Reorder the R1CS instance so that the public inputs are at the beginning.
    pub fn reorder_for_public_inputs(&mut self) {
        let num_rows = self.r1cs.num_constraints();

        for (i, pub_index) in self.public_input_indices.iter().enumerate() {
            let src_index = pub_index.get();
            let target_index = i as u32 + 1; // +1 because index 0 is reserved for the constant 1

            for row in 0..num_rows {
                // Swap the entries in A, B, C matrices
                self.r1cs.a.swap_indices(row, src_index, target_index);
                self.r1cs.b.swap_indices(row, src_index, target_index);
                self.r1cs.c.swap_indices(row, src_index, target_index);
            }
        }
    }

    /// Reorder the witness so that the public inputs are at the beginning.
    pub fn reorder_witness_for_public_inputs<D>(&self, witness: &mut [D]) {
        for (i, pub_index) in self.public_input_indices.iter().enumerate() {
            let src_index = pub_index.get() as usize;
            let target_index = i + 1; // +1 because index 0 is reserved for the constant 1
            witness.swap(src_index, target_index);
        }
    }
}

/// Complete a partial witness with random values.
#[instrument(skip_all, fields(size = witness.len()))]
pub fn fill_witness<F: PrimeField>(witness: Vec<Option<F>>) -> eyre::Result<Vec<F>> {
    // TODO: Use better entropy source and proper sampling.
    let mut rng = rand::thread_rng();
    let mut count = 0;
    let witness = witness
        .iter()
        .map(|f| {
            f.unwrap_or_else(|| {
                count += 1;
                F::from(rng.r#gen::<u128>())
            })
        })
        .collect::<Vec<_>>();
    info!("Filled witness with {count} random values");
    Ok(witness)
}

pub fn fill_witness_rep3<F: PrimeField>(
    witness: Vec<Option<Rep3AcvmType<F>>>,
    rep3_state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3AcvmType<F>>> {
    let mut count = 0;
    let witness = witness
        .iter()
        .map(|f| {
            f.to_owned().unwrap_or_else(|| {
                count += 1;
                rep3::arithmetic::rand(rep3_state).into()
            })
        })
        .collect::<Vec<_>>();
    info!("Filled witness with {count} random values");
    Ok(witness)
}
