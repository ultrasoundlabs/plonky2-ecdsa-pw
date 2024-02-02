use anyhow::Result;

use log::Level;

use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{GenericConfig, AlgebraicHasher, Hasher};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::gates::noop::NoopGate;
use plonky2::util::timing::TimingTree;
use plonky2::plonk::prover::prove;

pub type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner_proofs: &Vec<ProofTuple<F, InnerC, D>>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    for one_proof_ref in inner_proofs {
        let (inner_proof, inner_vd, inner_cd) = one_proof_ref;
        let pt = builder.add_virtual_proof_with_pis(inner_cd);
        pw.set_proof_with_pis_target(&pt, inner_proof);
        builder.register_public_inputs(&*pt.public_inputs);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);

        builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    }

   
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("prove", Level::Info);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

pub fn recursive_proof_2<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner_proofs: &Vec<ProofTuple<F, InnerC, D>>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    for one_proof_ref in inner_proofs {
        let (inner_proof, inner_vd, inner_cd) = one_proof_ref;
        let pt = builder.add_virtual_proof_with_pis(inner_cd);
        pw.set_proof_with_pis_target(&pt, inner_proof);
        builder.register_public_inputs(&*pt.public_inputs);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);

        builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    }

   
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("recursive:2 prove", Level::Info);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    let timing = TimingTree::new("recursive:2 verify", Level::Info);
    data.verify(proof.clone())?;
    timing.print();

    Ok((proof, data.verifier_only, data.common))
}
