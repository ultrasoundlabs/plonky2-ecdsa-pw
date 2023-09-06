#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use anyhow::Result;
use core::marker::PhantomData;
use log::{info, Level};

use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::GenericConfig;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2_field::types::{PrimeField, Field, PrimeField64};
use plonky2::util::timing::TimingTree;
use plonky2::plonk::circuit_data::CircuitConfig;

use crate::curve::curve_types::Curve;
use crate::curve::secp256k1::Secp256K1;
use crate::gadgets::biguint::WitnessBigUint;
use crate::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use crate::gadgets::glv::CircuitBuilderGlv;
use crate::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use crate::curve::ecdsa::{ECDSAPublicKey, ECDSASignature};
use crate::gadgets::recursive_proof::ProofTuple;

pub trait RegisterNonNativePublicTarget<T: Field, F: RichField + Extendable<D>, const D: usize> {
    fn register_public_nonative_target(&self, builder: &mut CircuitBuilder<F, D>);
}
pub trait SetNonNativeTarget<T: Field + PrimeField, F: Field + PrimeField64, W: Witness<F>> {
    fn set_nonative_target(&self, pw: &mut  W, msg: &T);
}

impl <T: Field, F: RichField + Extendable<D>, const D: usize> RegisterNonNativePublicTarget<T, F, D> for NonNativeTarget<T> {
    fn register_public_nonative_target(&self, builder: &mut CircuitBuilder<F, D>) {
        for i in 0..self.value.num_limbs() {
            builder.register_public_input(self.value.get_limb(i).0);
        }
    }
}

impl <T: Field + PrimeField, F: Field + PrimeField64, W: Witness<F>> SetNonNativeTarget<T, F, W> for NonNativeTarget<T> {
    fn set_nonative_target(&self, pw: &mut  W, msg: &T) {
        pw.set_biguint_target(&self.value, &msg.to_canonical_biguint());
    }
}

#[derive(Clone, Debug)]
pub struct ECDSASecretKeyTarget<C: Curve>(pub NonNativeTarget<C::ScalarField>);

#[derive(Clone, Debug)]
pub struct ECDSAPublicKeyTarget<C: Curve>(pub AffinePointTarget<C>);

impl <C: Curve> ECDSAPublicKeyTarget<C> {
    pub fn register_public_input<F: RichField + Extendable<D>, const D: usize, >(&self, builder: &mut CircuitBuilder<F, D>) {
        self.0.x.register_public_nonative_target(builder);
        self.0.y.register_public_nonative_target(builder);
    }

    pub fn set_ecdsa_pk_target<F: Field + PrimeField64, W: Witness<F>>(&self, pw: &mut  W, pk: &ECDSAPublicKey<C>) {
        pw.set_biguint_target(&self.0.x.value, &pk.0.x.to_canonical_biguint());
        pw.set_biguint_target(&self.0.y.value, &pk.0.y.to_canonical_biguint());
    }
}

#[derive(Clone, Debug)]
pub struct ECDSASignatureTarget<C: Curve> {
    pub r: NonNativeTarget<C::ScalarField>,
    pub s: NonNativeTarget<C::ScalarField>,
}

impl <C: Curve> ECDSASignatureTarget<C> {
    pub fn register_public_input<F: RichField + Extendable<D>, const D: usize, >(&self, builder: &mut CircuitBuilder<F, D>) {
        self.r.register_public_nonative_target(builder);
        self.s.register_public_nonative_target(builder);
    }

    pub fn set_ecdsa_signature_target<F: Field + PrimeField64, W: Witness<F>>(&self, pw: &mut  W, sig: &ECDSASignature<C>) {
        pw.set_biguint_target(&self.r.value, &sig.r.to_canonical_biguint());
        pw.set_biguint_target(&self.s.value, &sig.s.to_canonical_biguint());
    }
}

pub fn verify_message_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg: NonNativeTarget<Secp256K1Scalar>,
    sig: ECDSASignatureTarget<Secp256K1>,
    pk: ECDSAPublicKeyTarget<Secp256K1>,
) {
    let ECDSASignatureTarget { r, s } = sig;

    builder.curve_assert_valid(&pk.0);

    let c = builder.inv_nonnative(&s);
    let u1 = builder.mul_nonnative(&msg, &c);
    let u2 = builder.mul_nonnative(&r, &c);

    let point1 = fixed_base_curve_mul_circuit(builder, Secp256K1::GENERATOR_AFFINE, &u1);
    let point2 = builder.glv_mul(&pk.0, &u2);
    let point = builder.curve_add(&point1, &point2);

    let x = NonNativeTarget::<Secp256K1Scalar> {
        value: point.x.value,
        _phantom: PhantomData,
    };
    builder.connect_nonnative(&r, &x);
}

pub fn prove_ecdsa<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    msg: Secp256K1Scalar,
    sig: ECDSASignature<Secp256K1>,
    pk: ECDSAPublicKey<Secp256K1>,
) -> Result<ProofTuple<F, C, D>> {

    type Curve = Secp256K1;

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::wide_ecc_config());
    let msg_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();
    let pk_target: ECDSAPublicKeyTarget<Secp256K1> = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());

    let r_target = builder.add_virtual_nonnative_target();
    let s_target = builder.add_virtual_nonnative_target();
    let sig_target = ECDSASignatureTarget::<Curve> {
        r: r_target,
        s: s_target,
    };

    msg_target.register_public_nonative_target(&mut builder);
    pk_target.register_public_input(&mut builder);
    sig_target.register_public_input(&mut builder);

    verify_message_circuit(&mut builder, msg_target.clone(), sig_target.clone(), pk_target.clone());

    let mut pw = PartialWitness::new();
    msg_target.set_nonative_target(&mut pw, &msg);
    pk_target.set_ecdsa_pk_target(&mut pw, &pk);
    sig_target.set_ecdsa_signature_target(&mut pw, &sig);

    println!(
        "Constructing inner proof of `prove_ecdsa` with {} gates",
        builder.num_gates()
    );

    // info!(
    //     "Constructing inner proof of `prove_ecdsa` with {} gates",
    //     builder.num_gates()
    // );

    let data = builder.build::<C>();

    let timing = TimingTree::new("prove", Level::Info);
    let proof = data.prove(pw).unwrap();
    timing.print();

    let timing = TimingTree::new("verify", Level::Info);
    data.verify(proof.clone()).expect("verify error");
    timing.print();

    // test_serialization(&proof, &data.verifier_only, &data.common)?;
    Ok((proof, data.verifier_only, data.common))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::Sample;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use super::*;
    use crate::curve::curve_types::CurveScalar;
    use crate::curve::ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature};

    fn test_ecdsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg = Secp256K1Scalar::rand();
        let msg_target = builder.constant_nonnative(msg);

        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

        let sig = sign_message(msg, sk);

        let ECDSASignature { r, s } = sig;
        let r_target = builder.constant_nonnative(r);
        let s_target = builder.constant_nonnative(s);
        let sig_target = ECDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_wide() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::wide_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_prove_ecdsa() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let msg = Secp256K1Scalar::rand();
        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let sig = sign_message(msg, sk);

        println!("message digest: {:?}", msg);
        println!("sk: {:?}", sk);
        println!("pk: {:?}", pk);
        println!("signature: {:?}", sig);

        let ecdsa_proof = prove_ecdsa::<F, C, D>(msg, sig, pk).unwrap();
        println!("Num public inputs: {}", ecdsa_proof.2.num_public_inputs);
    }

    #[test]
    #[ignore]
    fn test_failure_fake_pk() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let msg = Secp256K1Scalar::rand();
        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());

        let sig = sign_message(msg, sk);

        let fake_pk = ECDSAPublicKey((CurveScalar(Secp256K1Scalar::rand()) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let ecdsa_proof = prove_ecdsa::<F, C, D>(msg, sig, fake_pk).unwrap();
        println!("Num public inputs: {}", ecdsa_proof.2.num_public_inputs);
    }

}
