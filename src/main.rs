#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use log::{info, Level, LevelFilter};

use plonky2::field::types::Sample;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

use plonky2_ecdsa::gadgets::recursive_proof::recursive_proof;
use plonky2_ecdsa::gadgets::ecdsa::prove_ecdsa;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::curve::curve_types::{CurveScalar, Curve};
use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature};

fn main() {
    // Initialize logging
    let mut env_builder = env_logger::Builder::from_default_env();
    env_builder.format_timestamp(None);
    env_builder.filter_level(LevelFilter::Info);
    env_builder.try_init().unwrap();

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    type Curve = Secp256K1;

    fn sample_ecdsa() -> (Secp256K1Scalar, ECDSAPublicKey<Curve>, ECDSASignature<Curve>) {
        let msg = Secp256K1Scalar::rand();
        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let sig = sign_message(msg, sk);

        (msg, pk, sig)
    }

    let config = CircuitConfig::standard_recursion_config();

    let ecdsa_1 = sample_ecdsa();
    let ecdsa_2 = sample_ecdsa();
    let ecdsa_3 = sample_ecdsa();

    // The performance bottleneck is due to the proving of a single `ecdsa` verification, and there needs to be a multithread version of the below proving
    println!("Prove single ecdsa starting...");
    let timing = TimingTree::new("prove ecdsa 1, 2, and 3", Level::Info);
    let mut proofs = std::vec::Vec::new();
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_1.0, ecdsa_1.2, ecdsa_1.1).expect("prove error 1"));
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_2.0, ecdsa_2.2, ecdsa_2.1).expect("prove error 2"));
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_3.0, ecdsa_3.2, ecdsa_3.1).expect("prove error 3"));
    timing.print();
    println!("Prove single ecdsa ended and start recursive proving...");

    // Recursively verify the proof
    let timing = TimingTree::new("Recursively verify the proof", Level::Info);
    let middle = recursive_proof::<F, C, C, D>(&proofs, &config, None).expect("prove recursive error!");
    let (_, _, cd) = &middle;
    println!(
        "Single recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );
    timing.print();

    // Add a second layer of recursion to shrink the proof size further
    let timing = TimingTree::new("final prove and verify", Level::Info);
    let final_proof_vec = std::vec![middle];
    let outer = recursive_proof::<F, C, C, D>(&final_proof_vec, &config, None).expect("prove final error!");
    let (_, _, cd) = &outer;
    println!(
        "Double recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );
    timing.print();
}
