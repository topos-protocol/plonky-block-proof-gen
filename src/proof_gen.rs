use plonky2::util::timing::TimingTree;
use plonky2_evm::{all_stark::AllStark, config::StarkConfig};
use proof_protocol_decoder::types::TxnProofGenIR;

use crate::{
    proof_types::{
        AggregatableProof, GeneratedAggProof, GeneratedBlockProof, GeneratedTxnProof, ProofCommon,
    },
    prover_state::ProverState,
};

pub type ProofGenResult<T> = Result<T, ProofGenError>;

// Plonky2 is still using `anyhow` for proof gen, and since this is a library,
// it's probably best if we at least convert it to a `String`.
#[derive(Debug)]
pub struct ProofGenError(pub String);

impl std::fmt::Display for ProofGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

impl std::error::Error for ProofGenError {}

impl From<String> for ProofGenError {
    fn from(v: String) -> Self {
        Self(v)
    }
}

/// Generate a txn proof from proof IR data.
pub fn generate_txn_proof(
    p_state: &ProverState,
    start_info: TxnProofGenIR,
) -> ProofGenResult<GeneratedTxnProof> {
    let b_height = start_info.b_height();
    let txn_idx = start_info.txn_idx;
    let deltas = start_info.deltas();

    let (txn_proof_intern, p_vals) = p_state
        .state
        .prove_root(
            &AllStark::default(),
            &StarkConfig::standard_fast_config(),
            start_info.gen_inputs,
            &mut TimingTree::default(),
        )
        .map_err(|err| err.to_string())?;

    let common = ProofCommon {
        b_height,
        deltas,
        roots_before: p_vals.trie_roots_before.clone(),
        roots_after: p_vals.trie_roots_after.clone(),
    };

    Ok(GeneratedTxnProof {
        txn_idx,
        common,
        intern: txn_proof_intern,
        public_values: p_vals,
    })
}

/// Generate a agg proof from two child proofs.
///
/// Note that the child proofs may be either txn or agg proofs.
pub fn generate_agg_proof(
    p_state: &ProverState,
    lhs_child: &AggregatableProof,
    rhs_child: &AggregatableProof,
) -> ProofGenResult<GeneratedAggProof> {
    let (agg_proof_intern, p_vals) = p_state
        .state
        .prove_aggregation(
            lhs_child.is_agg(),
            &lhs_child.intern(),
            lhs_child.public_values(),
            rhs_child.is_agg(),
            &rhs_child.intern(),
            rhs_child.public_values(),
        )
        .map_err(|err| err.to_string())?;

    let common = ProofCommon {
        b_height: lhs_child.b_height(),
        deltas: p_vals.extra_block_data.clone().into(),
        roots_before: p_vals.trie_roots_before.clone(),
        roots_after: p_vals.trie_roots_after.clone(),
    };

    Ok(GeneratedAggProof {
        common,
        underlying_txns: lhs_child
            .underlying_txns()
            .combine(&rhs_child.underlying_txns()),
        intern: agg_proof_intern,
        public_values: p_vals,
    })
}

/// Generate a block proof.
///
/// Note that `prev_opt_parent_b_proof` is able to be `None` on checkpoint
/// heights.
pub fn generate_block_proof(
    p_state: &ProverState,
    prev_opt_parent_b_proof: Option<&GeneratedBlockProof>,
    curr_block_agg_proof: &GeneratedAggProof,
) -> ProofGenResult<GeneratedBlockProof> {
    let b_height = curr_block_agg_proof.common.b_height;
    let parent_intern = prev_opt_parent_b_proof.map(|p| &p.intern);

    let (b_proof_intern, p_vals) = p_state
        .state
        .prove_block(
            parent_intern,
            &curr_block_agg_proof.intern,
            curr_block_agg_proof.public_values.clone(),
        )
        .map_err(|err| err.to_string())?;

    Ok(GeneratedBlockProof {
        b_height,
        intern: b_proof_intern,
        public_values: p_vals,
    })
}
