// The files in this folder are copied from https://github.com/worldfnd/ProveKit/tree/main/noir-r1cs and modified/extended to fit our MPC needs.

pub(crate) mod binops;
pub(crate) mod digits;
pub(crate) mod groth16;
pub(crate) mod interner;
pub(crate) mod memory;
pub mod noir_proof_schema;
pub(crate) mod noir_to_r1cs;
#[expect(clippy::module_inception)]
pub(crate) mod r1cs;
pub(crate) mod r1cs_solver;
pub(crate) mod ram;
pub(crate) mod range_check;
pub(crate) mod rom;
pub(crate) mod sparse_matrix;

pub(crate) use acir::FieldElement as NoirElement;
use ark_ff::PrimeField;
use num_bigint::BigUint;

#[inline(always)]
pub fn noir_to_native<F: PrimeField>(n: NoirElement) -> F {
    let limbs: BigUint = n.into_repr().into();
    F::from(limbs)
}
