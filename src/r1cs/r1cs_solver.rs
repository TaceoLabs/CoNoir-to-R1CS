use crate::r1cs::{
    binops::BINOP_ATOMIC_BITS, digits::DigitalDecompositionWitnesses, noir_to_native,
    noir_to_r1cs::ConstantOrR1CSWitness, ram::SpiceWitnesses,
};
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType, mpc::NoirWitnessExtensionProtocol};
use mpc_core::serde_compat::{ark_de, ark_se};
use mpc_net::Network;

use {
    acir::{FieldElement as NoirFieldElement, native_types::WitnessMap},
    ark_ff::PrimeField,
    rand::Rng,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SumTerm<F: PrimeField>(
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub Option<F>,
    pub usize,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantTerm<F: PrimeField>(
    pub usize,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub F,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WitnessCoefficient<F: PrimeField>(
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub F,
    pub usize,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProductLinearTerm<F: PrimeField>(
    pub usize,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub F,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub F,
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Indicates how to solve for a collection of R1CS witnesses in terms of
/// earlier (i.e. already solved for) R1CS witnesses and/or ACIR witness values.
pub enum WitnessBuilder<F: PrimeField> {
    /// Constant value, used for the constant one witness & e.g. static lookups
    /// (witness index, constant value)
    Constant(ConstantTerm<F>),
    /// A witness value carried over from the ACIR circuit (at the specified
    /// ACIR witness index) (includes ACIR inputs and outputs)
    /// (witness index, ACIR witness index)
    Acir(usize, usize),
    /// A linear combination of witness values, where the coefficients are field
    /// elements. First argument is the witness index of the sum.
    /// Vector consists of (optional coefficient, witness index) tuples, one for
    /// each summand. The coefficient is optional, and if it is None, the
    /// coefficient is 1.
    Sum(usize, Vec<SumTerm<F>>),
    /// The product of the values at two specified witness indices
    /// (witness index, operand witness index a, operand witness index b)
    Product(usize, usize, usize),
    /// Solves for the number of times that each memory address occurs in
    /// read-only memory. Arguments: (first witness index, range size,
    /// vector of all witness indices for values purported to be in the range)
    MultiplicitiesForRange(usize, usize, Vec<usize>),
    /// A Fiat-Shamir challenge value
    /// (witness index)
    Challenge(usize),
    /// For solving for the denominator of an indexed lookup.
    /// Fields are (witness index, sz_challenge, (index_coeff, index),
    /// rs_challenge, value).
    IndexedLogUpDenominator(usize, usize, WitnessCoefficient<F>, usize, usize),
    /// The inverse of the value at a specified witness index
    /// (witness index, operand witness index)
    Inverse(usize, usize),
    /// Products with linear operations on the witness indices.
    /// Fields are ProductLinearOperation(witness_idx, (index, a, b), (index, c,
    /// d)) such that we wish to compute (ax + b) * (cx + d).
    ProductLinearOperation(usize, ProductLinearTerm<F>, ProductLinearTerm<F>),
    /// For solving for the denominator of a lookup (non-indexed).
    /// Field are (witness index, sz_challenge, (value_coeff, value)).
    LogUpDenominator(usize, usize, WitnessCoefficient<F>),
    /// Builds the witnesses values required for the mixed base digital
    /// decomposition of other witness values.
    DigitalDecomposition(DigitalDecompositionWitnesses),
    /// A factor of the multiset check used in read/write memory checking.
    /// Values: (witness index, sz_challenge, rs_challenge, (addr,
    /// addr_witness), value, (timer, timer_witness)) where sz_challenge,
    /// rs_challenge, addr_witness, timer_witness are witness indices.
    /// Solver computes:
    /// sz_challenge - (addr * addr_witness + rs_challenge * value +
    /// rs_challenge * rs_challenge * timer * timer_witness)
    SpiceMultisetFactor(
        usize,
        usize,
        usize,
        WitnessCoefficient<F>,
        usize,
        WitnessCoefficient<F>,
    ),
    /// Builds the witnesses values required for the Spice memory model.
    /// (Note that some witness values are already solved for by the ACIR
    /// solver.)
    SpiceWitnesses(SpiceWitnesses),
    /// A witness value for the denominator of a bin op lookup.
    /// Arguments: `(witness index, sz_challenge, rs_challenge,
    /// rs_challenge_sqrd, lhs, rhs, output)`, where `lhs`, `rhs`, and
    /// `output` are either constant or witness values.
    BinOpLookupDenominator(
        usize,
        usize,
        usize,
        usize,
        ConstantOrR1CSWitness<F>,
        ConstantOrR1CSWitness<F>,
        ConstantOrR1CSWitness<F>,
    ),
    /// Witness values for the number of times that each pair of input values
    /// occurs in the bin op.
    MultiplicitiesForBinOp(
        usize,
        Vec<(ConstantOrR1CSWitness<F>, ConstantOrR1CSWitness<F>)>,
    ),
    /// A Bit-decomposition constraint
    /// (source_witness, result_witnesses)
    BitDecomposition(usize, Vec<usize>),
}

impl<F: PrimeField> WitnessBuilder<F> {
    /// The number of witness values that this builder writes to the witness
    /// vector.
    pub fn num_witnesses(&self) -> usize {
        match self {
            WitnessBuilder::MultiplicitiesForRange(_, range_size, _) => *range_size,
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.num_witnesses,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => {
                spice_witnesses_struct.num_witnesses
            }
            WitnessBuilder::MultiplicitiesForBinOp(..) => 2usize.pow(2 * BINOP_ATOMIC_BITS as u32),
            WitnessBuilder::BitDecomposition(_, result) => result.len(),
            _ => 1,
        }
    }

    /// Return the index of the first witness value that this builder writes to.
    pub fn first_witness_idx(&self) -> usize {
        match self {
            WitnessBuilder::Constant(ConstantTerm(start_idx, _)) => *start_idx,
            WitnessBuilder::Acir(start_idx, _) => *start_idx,
            WitnessBuilder::Sum(start_idx, _) => *start_idx,
            WitnessBuilder::Product(start_idx, ..) => *start_idx,
            WitnessBuilder::MultiplicitiesForRange(start_idx, ..) => *start_idx,
            WitnessBuilder::IndexedLogUpDenominator(start_idx, ..) => *start_idx,
            WitnessBuilder::Challenge(start_idx) => *start_idx,
            WitnessBuilder::Inverse(start_idx, _) => *start_idx,
            WitnessBuilder::LogUpDenominator(start_idx, ..) => *start_idx,
            WitnessBuilder::ProductLinearOperation(start_idx, ..) => *start_idx,
            WitnessBuilder::DigitalDecomposition(dd_struct) => dd_struct.first_witness_idx,
            WitnessBuilder::SpiceMultisetFactor(start_idx, ..) => *start_idx,
            WitnessBuilder::SpiceWitnesses(spice_witnesses_struct) => {
                spice_witnesses_struct.first_witness_idx
            }

            WitnessBuilder::BinOpLookupDenominator(start_idx, ..) => *start_idx,
            WitnessBuilder::MultiplicitiesForBinOp(start_idx, _) => *start_idx,
            WitnessBuilder::BitDecomposition(_, result) => result[0],
        }
    }

    /// As per solve(), but additionally appends the solved witness values to
    /// the transcript.
    pub fn solve_and_append_to_transcript(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirFieldElement>,
        witness: &mut [Option<F>],
        transcript: &mut MockTranscript,
    ) {
        self.solve(acir_witness_idx_to_value_map, witness, transcript);

        for i in 0..self.num_witnesses() {
            transcript.append(witness[self.first_witness_idx() + i].unwrap());
        }
    }

    /// Solves for the witness value(s) specified by this builder and writes
    /// them to the witness vector.
    pub fn solve(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<NoirFieldElement>,
        witness: &mut [Option<F>],
        transcript: &mut MockTranscript,
    ) {
        match self {
            WitnessBuilder::Constant(ConstantTerm(witness_idx, c)) => {
                witness[*witness_idx] = Some(*c);
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = Some(noir_to_native(
                    *acir_witness_idx_to_value_map
                        .get_index(*acir_witness_idx as u32)
                        .unwrap(),
                ));
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                witness[*witness_idx] = Some(
                    operands
                        .iter()
                        .map(|SumTerm(coeff, witness_idx)| {
                            if let Some(coeff) = coeff {
                                *coeff * witness[*witness_idx].unwrap()
                            } else {
                                witness[*witness_idx].unwrap()
                            }
                        })
                        .fold(F::zero(), |acc, x| acc + x),
                );
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a: F = witness[*operand_idx_a].unwrap();
                let b: F = witness[*operand_idx_b].unwrap();
                witness[*witness_idx] = Some(a * b);
            }
            WitnessBuilder::Inverse(witness_idx, operand_idx) => {
                let operand: F = witness[*operand_idx].unwrap();
                witness[*witness_idx] = Some(operand.inverse().unwrap());
            }
            WitnessBuilder::IndexedLogUpDenominator(
                witness_idx,
                sz_challenge,
                WitnessCoefficient(index_coeff, index),
                rs_challenge,
                value,
            ) => {
                let index = witness[*index].unwrap();
                let value = witness[*value].unwrap();
                let rs_challenge = witness[*rs_challenge].unwrap();
                let sz_challenge = witness[*sz_challenge].unwrap();
                witness[*witness_idx] =
                    Some(sz_challenge - (*index_coeff * index + rs_challenge * value));
            }
            WitnessBuilder::MultiplicitiesForRange(start_idx, range_size, value_witnesses) => {
                let mut multiplicities = vec![0u32; *range_size];
                for value_witness_idx in value_witnesses {
                    // If the value is representable as just a u64, then it should be the least
                    // significant value in the BigInt representation.
                    let value = witness[*value_witness_idx].unwrap().into_bigint().as_ref()[0];
                    multiplicities[value as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[start_idx + i] = Some(F::from(*count));
                }
            }
            WitnessBuilder::Challenge(witness_idx) => {
                witness[*witness_idx] = Some(transcript.draw_challenge());
            }
            WitnessBuilder::LogUpDenominator(
                witness_idx,
                sz_challenge,
                WitnessCoefficient(value_coeff, value),
            ) => {
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap() - (*value_coeff * witness[*value].unwrap()),
                );
            }
            WitnessBuilder::ProductLinearOperation(
                witness_idx,
                ProductLinearTerm(x, a, b),
                ProductLinearTerm(y, c, d),
            ) => {
                witness[*witness_idx] =
                    Some((*a * witness[*x].unwrap() + *b) * (*c * witness[*y].unwrap() + *d));
            }
            WitnessBuilder::DigitalDecomposition(dd_struct) => {
                dd_struct.solve(witness);
            }
            WitnessBuilder::SpiceMultisetFactor(
                witness_idx,
                sz_challenge,
                rs_challenge,
                WitnessCoefficient(addr, addr_witness),
                value,
                WitnessCoefficient(timer, timer_witness),
            ) => {
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (*addr * witness[*addr_witness].unwrap()
                            + witness[*rs_challenge].unwrap() * witness[*value].unwrap()
                            + witness[*rs_challenge].unwrap()
                                * witness[*rs_challenge].unwrap()
                                * *timer
                                * witness[*timer_witness].unwrap()),
                );
            }
            WitnessBuilder::SpiceWitnesses(spice_witnesses) => {
                spice_witnesses.solve(witness);
            }
            WitnessBuilder::BinOpLookupDenominator(
                witness_idx,
                sz_challenge,
                rs_challenge,
                rs_challenge_sqrd,
                lhs,
                rhs,
                output,
            ) => {
                let lhs = match lhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let rhs = match rhs {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                let output = match output {
                    ConstantOrR1CSWitness::Constant(c) => *c,
                    ConstantOrR1CSWitness::Witness(witness_idx) => witness[*witness_idx].unwrap(),
                };
                witness[*witness_idx] = Some(
                    witness[*sz_challenge].unwrap()
                        - (lhs
                            + witness[*rs_challenge].unwrap() * rhs
                            + witness[*rs_challenge_sqrd].unwrap() * output),
                );
            }
            WitnessBuilder::MultiplicitiesForBinOp(witness_idx, operands) => {
                let mut multiplicities = vec![0u32; 2usize.pow(2 * BINOP_ATOMIC_BITS as u32)];
                for (lhs, rhs) in operands {
                    let lhs = match lhs {
                        ConstantOrR1CSWitness::Constant(c) => *c,
                        ConstantOrR1CSWitness::Witness(witness_idx) => {
                            witness[*witness_idx].unwrap()
                        }
                    };
                    let rhs = match rhs {
                        ConstantOrR1CSWitness::Constant(c) => *c,
                        ConstantOrR1CSWitness::Witness(witness_idx) => {
                            witness[*witness_idx].unwrap()
                        }
                    };
                    let index = (lhs.into_bigint().as_ref()[0] << BINOP_ATOMIC_BITS)
                        + rhs.into_bigint().as_ref()[0];
                    multiplicities[index as usize] += 1;
                }
                for (i, count) in multiplicities.iter().enumerate() {
                    witness[witness_idx + i] = Some(F::from(*count));
                }
            }
            WitnessBuilder::BitDecomposition(src, des) => {
                let src: F = witness[*src].unwrap();
                let mut bits = src.into_bigint();
                for d in des.iter() {
                    let bit = bits.as_ref()[0] & 1;
                    bits >>= 1;
                    witness[*d] = Some(F::from(bit));
                }
            }
        }
    }

    /// Solves for the witness value(s) specified by this builder and writes
    /// them to the witness vector.
    pub fn solve_rep3<N: Network>(
        &self,
        acir_witness_idx_to_value_map: &WitnessMap<Rep3AcvmType<F>>,
        witness: &mut [Option<Rep3AcvmType<F>>],
        driver: &mut Rep3AcvmSolver<F, N>,
    ) -> eyre::Result<()> {
        match self {
            WitnessBuilder::Constant(ConstantTerm(witness_idx, c)) => {
                witness[*witness_idx] = Some((*c).into());
            }
            WitnessBuilder::Acir(witness_idx, acir_witness_idx) => {
                witness[*witness_idx] = Some(
                    acir_witness_idx_to_value_map
                        .get_index(*acir_witness_idx as u32)
                        .unwrap()
                        .to_owned(),
                );
            }
            WitnessBuilder::Sum(witness_idx, operands) => {
                let mut sum = Rep3AcvmType::default();

                for SumTerm(coeff, witness_idx) in operands.iter() {
                    let val = if let Some(coeff) = coeff {
                        driver.mul_with_public(*coeff, witness[*witness_idx].to_owned().unwrap())
                    } else {
                        witness[*witness_idx].to_owned().unwrap()
                    };
                    sum = driver.add(sum, val);
                }
                witness[*witness_idx] = Some(sum);
            }
            WitnessBuilder::Product(witness_idx, operand_idx_a, operand_idx_b) => {
                let a = witness[*operand_idx_a].to_owned().unwrap();
                let b = witness[*operand_idx_b].to_owned().unwrap();
                let mul = driver.mul(a, b)?;
                witness[*witness_idx] = Some(mul);
            }
            WitnessBuilder::Inverse(witness_idx, operand_idx) => {
                let operand = witness[*operand_idx].to_owned().unwrap();
                let inv = driver.invert(operand)?;
                witness[*witness_idx] = Some(inv);
            }
            WitnessBuilder::BitDecomposition(src, des) => {
                let src = witness[*src].to_owned().unwrap();
                match src {
                    Rep3AcvmType::Public(val) => {
                        let mut bits = val.into_bigint();
                        for d in des.iter() {
                            let bit = bits.as_ref()[0] & 1;
                            bits >>= 1;
                            witness[*d] = Some(Rep3AcvmType::from(F::from(bit)));
                        }
                    }
                    Rep3AcvmType::Shared(val) => {
                        let decomp = driver.decompose_arithmetic(val, des.len(), 1)?;
                        debug_assert_eq!(des.len(), decomp.len());
                        for (d, bit) in des.iter().zip(decomp) {
                            witness[*d] = Some(Rep3AcvmType::from(bit));
                        }
                    }
                }
            }
            x => panic!("Unsupported operation for Rep3 solving: {x:?}"),
        }
        Ok(())
    }
}

/// Mock transcript. To be replaced.
pub struct MockTranscript {}

impl Default for MockTranscript {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTranscript {
    pub fn new() -> Self {
        Self {}
    }

    pub fn append<F: PrimeField>(&mut self, _value: F) {}

    pub fn draw_challenge<F: PrimeField>(&mut self) -> F {
        let mut rng = rand::thread_rng();
        let n: u32 = rng.r#gen();
        n.into()
    }
}
