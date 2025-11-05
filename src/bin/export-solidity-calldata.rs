use std::{fs::File, path::PathBuf, process::ExitCode};

use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, Validate};
use circom_types::groth16::{ConstraintMatricesWrapper, JsonPublicInput};
use clap::Parser;
use co_circom::{CheckElement, Groth16ZKey, ProvingKey};
use co_groth16::Proof;
use co_noir::Bn254;
use tracing::Instrument;

#[derive(Parser, Debug)]
pub struct Config {
    /// Output path to the matrices file.
    #[clap(long, env = "MATRICES_PATH", default_value = "matrices.bin")]
    pub matrices_path: PathBuf,

    /// Output path to the proving key file.
    #[clap(long, env = "PROVING_KEY_PATH", default_value = "pk.bin")]
    pub pk_path: PathBuf,

    /// The path to the noir program artifact
    #[clap(long, env = "PROOF_PATH")]
    pub proof_path: PathBuf,

    /// Output path to the matrices file.
    #[clap(long, env = "PUBLIC_INPUTS_PATH")]
    pub public_inputs_path: PathBuf,

    /// Use uncompressed serialization
    #[clap(long, env = "UNCOMPRESSED")]
    pub uncompressed: bool,
}
fn main() -> eyre::Result<ExitCode> {
    let config = Config::parse();
    let mode = if config.uncompressed {
        ark_serialize::Compress::No
    } else {
        ark_serialize::Compress::Yes
    };
    let proof =
        Proof::<Bn254>::deserialize_with_mode(File::open(config.proof_path)?, mode, Validate::Yes)?;

    let public_input: JsonPublicInput<ark_bn254::Fr> =
        serde_json::from_reader(File::open(config.public_inputs_path)?)?;

    let pk = ProvingKey::<Bn254>::deserialize_with_mode(
        File::open(config.pk_path)?,
        mode,
        Validate::Yes,
    )?;
    let matrices = ConstraintMatricesWrapper::<ark_bn254::Fr>::deserialize_with_mode(
        File::open(config.matrices_path)?,
        mode,
        Validate::Yes,
    )?
    .0;
    Ok(ExitCode::SUCCESS)
}
