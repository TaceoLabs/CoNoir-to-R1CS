use ark_relations::r1cs::ConstraintMatrices;
use mpc_core::protocols::rep3::Rep3PrimeFieldShare;
use {
    crate::r1cs::{
        interner::Interner,
        r1cs_solver::{MockTranscript, WitnessBuilder},
        sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
    },
    acir::{FieldElement as NoirFieldElement, native_types::WitnessMap},
    ark_ff::PrimeField,
    co_acvm::{Rep3AcvmSolver, Rep3AcvmType},
    eyre::ensure,
    mpc_net::Network,
    serde::{Deserialize, Serialize},
    tracing::instrument,
};

/// Represents a R1CS constraint system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1CS<F: PrimeField> {
    pub num_public_inputs: usize,
    pub interner: Interner<F>,
    pub a: SparseMatrix,
    pub b: SparseMatrix,
    pub c: SparseMatrix,
}

impl<F: PrimeField> Default for R1CS<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> R1CS<F> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_public_inputs: 1,
            interner: Interner::new(),
            a: SparseMatrix::new(0, 0),
            b: SparseMatrix::new(0, 0),
            c: SparseMatrix::new(0, 0),
        }
    }

    #[must_use]
    pub const fn a(&self) -> HydratedSparseMatrix<'_, F> {
        self.a.hydrate(&self.interner)
    }

    #[must_use]
    pub const fn b(&self) -> HydratedSparseMatrix<'_, F> {
        self.b.hydrate(&self.interner)
    }

    #[must_use]
    pub const fn c(&self) -> HydratedSparseMatrix<'_, F> {
        self.c.hydrate(&self.interner)
    }

    /// The number of constraints in the R1CS instance.
    pub const fn num_constraints(&self) -> usize {
        self.a.num_rows
    }

    /// The number of witnesses in the R1CS instance (including the constant one
    /// witness).
    pub const fn num_witnesses(&self) -> usize {
        self.a.num_cols
    }

    // Increase the size of the R1CS matrices to the specified dimensions.
    pub fn grow_matrices(&mut self, num_rows: usize, num_cols: usize) {
        self.a.grow(num_rows, num_cols);
        self.b.grow(num_rows, num_cols);
        self.c.grow(num_rows, num_cols);
    }

    /// Add a new witnesses to the R1CS instance.
    pub fn add_witnesses(&mut self, count: usize) {
        self.grow_matrices(self.num_constraints(), self.num_witnesses() + count);
    }

    /// Add an R1CS constraint.
    pub fn add_constraint(&mut self, a: &[(F, usize)], b: &[(F, usize)], c: &[(F, usize)]) {
        let next_constraint_idx = self.num_constraints();
        self.grow_matrices(self.num_constraints() + 1, self.num_witnesses());

        for (coeff, witness_idx) in a.iter().copied() {
            self.a.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
        for (coeff, witness_idx) in b.iter().copied() {
            self.b.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
        for (coeff, witness_idx) in c.iter().copied() {
            self.c.set(
                next_constraint_idx,
                witness_idx,
                self.interner.intern(coeff),
            );
        }
    }

    /// Given the ACIR witness values, solve for the R1CS witness values.
    pub fn solve_witness_vec(
        &self,
        witness_builder_vec: &[WitnessBuilder<F>],
        acir_witness_idx_to_value_map: &WitnessMap<NoirFieldElement>,
        transcript: &mut MockTranscript,
    ) -> Vec<Option<F>> {
        let mut witness = vec![None; self.num_witnesses()];
        witness_builder_vec.iter().for_each(|witness_builder| {
            witness_builder.solve_and_append_to_transcript(
                acir_witness_idx_to_value_map,
                &mut witness,
                transcript,
            );
        });
        witness
    }

    pub fn solve_witness_vec_rep3<N: Network>(
        &self,
        witness_builder_vec: &[WitnessBuilder<F>],
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<F>>,
        driver: &mut Rep3AcvmSolver<F, N>,
    ) -> eyre::Result<Vec<Option<Rep3AcvmType<F>>>> {
        let mut witness = vec![None; self.num_witnesses()];
        for witness_builder in witness_builder_vec.iter() {
            witness_builder.solve_rep3(acir_witness_idx_to_value_map, &mut witness, driver)?;
        }
        Ok(witness)
    }

    pub fn solve_witness_vec_rep3_with_bitdecomp_witness<N: Network>(
        &self,
        witness_builder_vec: &[WitnessBuilder<F>],
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<F>>,
        bitdecomps: Vec<Rep3PrimeFieldShare<F>>,
        driver: &mut Rep3AcvmSolver<F, N>,
    ) -> eyre::Result<Vec<Option<Rep3AcvmType<F>>>> {
        let mut bitdecomps_iter = bitdecomps.into_iter();
        let mut witness = vec![None; self.num_witnesses()];
        for witness_builder in witness_builder_vec.iter() {
            witness_builder.solve_rep3_with_bitdecomp_witness(
                acir_witness_idx_to_value_map,
                &mut witness,
                &mut bitdecomps_iter,
                driver,
            )?;
        }
        assert!(
            bitdecomps_iter.next().is_none(),
            "Too many bit decomposition witnesses provided"
        );
        Ok(witness)
    }

    // Tests R1CS Witness satisfaction given the constraints provided by the
    // R1CS Matrices.
    #[instrument(skip_all, fields(size = witness.len()))]
    pub fn test_witness_satisfaction(&self, witness: &[F]) -> eyre::Result<()> {
        ensure!(
            witness.len() == self.num_witnesses(),
            "Witness size does not match"
        );

        // Verify
        let a = self.a() * witness;
        let b = self.b() * witness;
        let c = self.c() * witness;
        for (row, ((a, b), c)) in a
            .into_iter()
            .zip(b.into_iter())
            .zip(c.into_iter())
            .enumerate()
        {
            ensure!(a * b == c, "Constraint {row} failed");
        }
        Ok(())
    }

    fn matrix_to_ark_matrix(mat: HydratedSparseMatrix<'_, F>) -> (Vec<Vec<(F, usize)>>, usize) {
        let num_constraints = mat.matrix.num_rows;
        let mut res_mat = vec![Vec::new(); num_constraints];
        let mut num_non_zero = 0;

        for ((row, col), val) in mat.iter() {
            if val.is_zero() {
                continue;
            }
            num_non_zero += 1;
            res_mat[row].push((val, col));
        }

        (res_mat, num_non_zero)
    }

    pub fn to_ark_constraint_matrix(&self) -> ConstraintMatrices<F> {
        let num_constraints = self.num_constraints();
        let num_witnesses = self.num_witnesses();
        let num_public_inputs = self.num_public_inputs;

        let (a, a_num_non_zero) = Self::matrix_to_ark_matrix(self.a());
        let (b, b_num_non_zero) = Self::matrix_to_ark_matrix(self.b());
        let (c, c_num_non_zero) = Self::matrix_to_ark_matrix(self.c());

        ConstraintMatrices {
            num_instance_variables: num_public_inputs,
            num_witness_variables: num_witnesses - num_public_inputs,
            num_constraints,
            a_num_non_zero,
            b_num_non_zero,
            c_num_non_zero,
            a,
            b,
            c,
        }
    }
}
