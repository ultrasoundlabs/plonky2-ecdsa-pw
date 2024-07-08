#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use hex_literal::hex;

use num::BigUint;

use log::{info, Level, LevelFilter};

use plonky2::field::types::Sample;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;

use plonky2_ecdsa::gadgets::recursive_proof::recursive_proof;
use plonky2_ecdsa::gadgets::ecdsa::prove_ecdsa;
use plonky2_ecdsa::curve::secp256k1::Secp256K1;
use plonky2_ecdsa::curve::curve_types::{CurveScalar, Curve};
use plonky2_ecdsa::curve::ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature};
use plonky2_ecdsa::curve::curve_types::AffinePoint;

fn convert_byte_array_to_biguint(array: &[u8]) -> BigUint {
    let bigint = BigUint::from_bytes_le(array);
    let mut u32s = bigint.to_u32_digits();
    u32s.iter_mut().for_each(|x| *x = x.to_be());
    BigUint::from_slice(&u32s)
}

fn main() {
    // Initialize logging
    let mut log_builder = env_logger::Builder::from_default_env();
    log_builder.format_timestamp(None);
    log_builder.filter_level(LevelFilter::Info);
    log_builder.try_init().unwrap();

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    type Curve = Secp256K1;

    fn sample_ecdsa() -> (Secp256K1Scalar, ECDSAPublicKey<Curve>, ECDSASignature<Curve>) {
        let msg = Secp256K1Scalar::rand();

        let public_key = hex!("12b50d6895e6010f0f7fb4e6eba00fb4eca46229649b60520bc09f8bb3b9dc26d66ab4752a2f3bd6a5e517b6a173a0a6f1cbe4867a0195d2bfeb9f823817a9e0");
        let signature = hex!("b81286a92ee17057441182938c4c74113eb7bb580c3e1ad2d6440603182085317e8d1eb51453e4b058a1b6b231b7be8214b920969df35eb2dc0988e27048edd7");

        let x_coord_biguint = convert_byte_array_to_biguint(&public_key[0..32]);
        let y_coord_biguint = convert_byte_array_to_biguint(&public_key[32..64]);
        let r_biguint = convert_byte_array_to_biguint(&signature[0..32]);
        let s_biguint = convert_byte_array_to_biguint(&signature[32..64]);
        
        let structured_public_key = ECDSAPublicKey::<Curve> {
            0: AffinePoint {
                x: <Secp256K1 as plonky2_ecdsa::curve::curve_types::Curve>::BaseField::from_noncanonical_biguint(x_coord_biguint),
                y: <Secp256K1 as plonky2_ecdsa::curve::curve_types::Curve>::BaseField::from_noncanonical_biguint(y_coord_biguint),
                zero: false,
            }
        };
        let structured_signature = ECDSASignature::<Curve> {
            r: <Secp256K1 as plonky2_ecdsa::curve::curve_types::Curve>::ScalarField::from_noncanonical_biguint(r_biguint),
            s: <Secp256K1 as plonky2_ecdsa::curve::curve_types::Curve>::ScalarField::from_noncanonical_biguint(s_biguint),
        };

        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let sig = sign_message(msg, sk);

        println!("msg: {:?}", msg);

        println!("pk: {:?}", pk);
        println!("sig: {:?}", sig);

        println!("structured_public_key: {:?}", structured_public_key);
        println!("structured_signature: {:?}", structured_signature);

        (msg, structured_public_key, structured_signature)
    }

    let config = CircuitConfig::standard_recursion_config();

    let ecdsa_1 = sample_ecdsa();
    let ecdsa_2 = sample_ecdsa();
    let ecdsa_3 = sample_ecdsa();

    // The performance bottleneck is due to the proving of a single `ecdsa` verification, and there needs to be a multithread version of the below proving
    info!("Prove single ecdsa starting...");
    let timing = TimingTree::new("prove ecdsa 1, 2, and 3", Level::Info);
    let mut proofs = std::vec::Vec::new();
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_1.0, ecdsa_1.2, ecdsa_1.1).expect("prove error 1"));
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_2.0, ecdsa_2.2, ecdsa_2.1).expect("prove error 2"));
    proofs.push(prove_ecdsa::<F, C, D>(ecdsa_3.0, ecdsa_3.2, ecdsa_3.1).expect("prove error 3"));
    timing.print();
    info!("Prove single ecdsa ended and start recursive proving...");

    // Recursively verify the proof
    let timing = TimingTree::new("Recursively verify the proof", Level::Info);
    let middle = recursive_proof::<F, C, C, D>(&proofs, &config, None).expect("prove recursive error!");
    let (_, _, cd) = &middle;
    info!(
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
    info!(
        "Double recursion proof degree {} = 2^{}",
        cd.degree(),
        cd.degree_bits()
    );
    timing.print();
}
