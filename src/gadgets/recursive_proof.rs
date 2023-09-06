use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs};

pub type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);
