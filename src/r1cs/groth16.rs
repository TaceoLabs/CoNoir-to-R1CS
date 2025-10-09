use crate::r1cs::r1cs::R1CS;
use ark_ec::{CurveGroup, scalar_mul::BatchMulPreprocessing};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::SynthesisError;
use co_noir::Pairing;
use rand::{CryptoRng, Rng};

impl<F: PrimeField> R1CS<F> {
    // This is extracted from ark-groth (generate_random_parameters_with_reduction)
    // TODO make a ceremnoy out of this
    pub fn generate_proving_key<P: Pairing<ScalarField = F>, R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> eyre::Result<ProvingKey<P>> {
        type D<F> = GeneralEvaluationDomain<F>;

        let alpha = F::rand(rng);
        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let delta = F::rand(rng);

        let g1_generator = P::G1::rand(rng);
        let g2_generator = P::G2::rand(rng);

        let domain_size = self.num_constraints() + self.num_public_inputs;
        let domain = D::<F>::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let t = domain.sample_element_outside_domain(rng);

        self.generate_proving_key_with_randomness(
            alpha,
            beta,
            gamma,
            delta,
            g1_generator,
            g2_generator,
            t,
        )
    }

    // This is extracted from ark-groth16 (generate_parameters_with_qap)
    #[expect(clippy::too_many_arguments)]
    pub fn generate_proving_key_with_randomness<P: Pairing<ScalarField = F>>(
        &self,
        alpha: F,
        beta: F,
        gamma: F,
        delta: F,
        g1_generator: P::G1,
        g2_generator: P::G2,
        t: F,
    ) -> eyre::Result<ProvingKey<P>> {
        type D<F> = GeneralEvaluationDomain<F>;

        // Following is the mapping of symbols from the Groth16 paper to this implementation
        // l -> num_instance_variables
        // m -> qap_num_variables
        // x -> t
        // t(x) - zt
        // u_i(x) -> a
        // v_i(x) -> b
        // w_i(x) -> c

        let num_instance_variables = self.num_public_inputs;
        let (a, b, c, zt, qap_num_variables, m_raw) = self.qap_reduction::<D<F>>(t)?;

        // Compute query densities
        let non_zero_a: usize = (0..qap_num_variables)
            .map(|i| usize::from(!a[i].is_zero()))
            .sum();

        let non_zero_b: usize = (0..qap_num_variables)
            .map(|i| usize::from(!b[i].is_zero()))
            .sum();

        let gamma_inverse = gamma.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;
        let delta_inverse = delta.inverse().ok_or(SynthesisError::UnexpectedIdentity)?;

        let gamma_abc = a[..num_instance_variables]
            .iter()
            .zip(&b[..num_instance_variables])
            .zip(&c[..num_instance_variables])
            .map(|((a, b), c)| (beta * a + (alpha * b) + c) * gamma_inverse)
            .collect::<Vec<_>>();

        let l = a[num_instance_variables..]
            .iter()
            .zip(&b[num_instance_variables..])
            .zip(&c[num_instance_variables..])
            .map(|((a, b), c)| (beta * a + (alpha * b) + c) * delta_inverse)
            .collect::<Vec<_>>();

        drop(c);

        // Compute B window table
        let g2_table = BatchMulPreprocessing::new(g2_generator, non_zero_b);

        // Compute the B-query in G2
        let b_g2_query = g2_table.batch_mul(&b);
        drop(g2_table);

        // Compute G window table
        let num_scalars = non_zero_a + non_zero_b + qap_num_variables + m_raw + 1;
        let g1_table = BatchMulPreprocessing::new(g1_generator, num_scalars);

        // Generate the R1CS proving key
        let alpha_g1 = g1_generator * alpha;
        let beta_g1 = g1_generator * beta;
        let beta_g2 = g2_generator * beta;
        let delta_g1 = g1_generator * delta;
        let delta_g2 = g2_generator * delta;

        // Compute the A-query
        let a_query = g1_table.batch_mul(&a);
        drop(a);

        // Compute the B-query in G1
        let b_g1_query = g1_table.batch_mul(&b);
        drop(b);

        // Compute the H-query
        let h_scalars = Self::h_query_scalars(m_raw - 1, t, zt, delta_inverse)?;
        let h_query = g1_table.batch_mul(&h_scalars);

        // Compute the L-query
        let l_query = g1_table.batch_mul(&l);
        drop(l);

        // Generate R1CS verification key
        let gamma_g2 = g2_generator * gamma;
        let gamma_abc_g1 = g1_table.batch_mul(&gamma_abc);
        drop(g1_table);

        let vk = VerifyingKey::<P> {
            alpha_g1: alpha_g1.into_affine(),
            beta_g2: beta_g2.into_affine(),
            gamma_g2: gamma_g2.into_affine(),
            delta_g2: delta_g2.into_affine(),
            gamma_abc_g1,
        };

        Ok(ProvingKey {
            vk,
            beta_g1: beta_g1.into_affine(),
            delta_g1: delta_g1.into_affine(),
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        })
    }

    // Copied from ark-groth16 (instance_map_with_evaluation)
    #[expect(clippy::type_complexity)]
    fn qap_reduction<D: EvaluationDomain<F>>(
        &self,
        t: F,
    ) -> eyre::Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize)> {
        let domain_size = self.num_constraints() + self.num_public_inputs;
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let zt = domain.evaluate_vanishing_polynomial(t);

        // Evaluate all Lagrange polynomials

        let u = domain.evaluate_all_lagrange_coefficients(t);

        let qap_num_variables = self.num_witnesses() - 1;

        let mut a = vec![F::zero(); qap_num_variables + 1];
        let mut b = vec![F::zero(); qap_num_variables + 1];
        let mut c = vec![F::zero(); qap_num_variables + 1];

        {
            let start = 0;
            let end = self.num_public_inputs;
            let num_constraints = self.num_constraints();
            a[start..end].copy_from_slice(&u[(start + num_constraints)..(end + num_constraints)]);
        }

        for (i, u_i) in u.iter().enumerate().take(self.num_constraints()) {
            for (index, coeff) in self.a().iter_row(i) {
                a[index] += &(*u_i * coeff);
            }
            for (index, coeff) in self.b().iter_row(i) {
                b[index] += &(*u_i * coeff);
            }
            for (index, coeff) in self.c().iter_row(i) {
                c[index] += &(*u_i * coeff);
            }
        }

        Ok((a, b, c, zt, qap_num_variables, domain_size))
    }

    fn h_query_scalars(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        let scalars = (0..max_power)
            .map(|i| zt * delta_inverse * t.pow([i as u64]))
            .collect::<Vec<_>>();
        Ok(scalars)
    }
}
