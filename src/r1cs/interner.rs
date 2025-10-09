use mpc_core::serde_compat::{ark_de, ark_se};
use {
    ark_ff::PrimeField,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interner<F: PrimeField> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    values: Vec<F>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternedFieldElement(usize);

impl<F: PrimeField> Default for Interner<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> Interner<F> {
    pub const fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Interning is slow in favour of faster lookups.
    pub fn intern(&mut self, value: F) -> InternedFieldElement {
        // Deduplicate
        if let Some(index) = self.values.iter().position(|v| *v == value) {
            return InternedFieldElement(index);
        }

        // Insert
        let index = self.values.len();
        self.values.push(value);
        InternedFieldElement(index)
    }

    pub fn get(&self, el: InternedFieldElement) -> Option<F> {
        self.values.get(el.0).copied()
    }
}
