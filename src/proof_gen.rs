use plonky2::util::timing::TimingTree;
use plonky2_evm::{all_stark::AllStark, config::StarkConfig, proof::PublicValues};

use crate::{
    proof_types::{
        AggregatableProof, BlockLevelData, GeneratedAggProof, GeneratedBlockProof,
        GeneratedTxnProof, ProofBeforeAndAfterDeltas, ProofCommon, TxnProofGenIR,
    },
    prover_state::ProverState,
    types::PlonkyProofIntern,
};

type ProofGenResult<T> = Result<T, ProofGenError>;

pub struct ProofGenError(pub(crate) String);

impl From<String> for ProofGenError {
    fn from(v: String) -> Self {
        Self(v)
    }
}

pub fn generate_txn_proof(
    p_state: &ProverState,
    start_info: TxnProofGenIR,
    b_data: BlockLevelData,
) -> ProofGenResult<GeneratedTxnProof> {
    let b_height = start_info.b_height;
    let txn_idx = start_info.txn_idx;
    let deltas = start_info.deltas.clone();

    let (txn_proof_intern, p_vals) = p_state
        .state
        .prove_root(
            &AllStark::default(),
            &StarkConfig::standard_fast_config(),
            start_info.into_generation_inputs(b_data),
            &mut TimingTree::default(),
        )
        .map_err(|err| err.to_string())?;

    let common = ProofCommon {
        b_height,
        deltas,
        roots_before: p_vals.trie_roots_before,
        roots_after: p_vals.trie_roots_after,
    };

    Ok(GeneratedTxnProof {
        txn_idx,
        common,
        intern: txn_proof_intern,
    })
}

pub fn generate_agg_proof(
    p_state: &ProverState,
    lhs_child: &AggregatableProof,
    rhs_child: &AggregatableProof,
    b_data: BlockLevelData,
) -> ProofGenResult<GeneratedAggProof> {
    let expanded_agg_proofs = expand_aggregatable_proofs(lhs_child, rhs_child, b_data);
    let deltas = expanded_agg_proofs.p_vals.extra_block_data.clone().into();

    let (agg_proof_intern, p_vals) = p_state
        .state
        .prove_aggregation(
            expanded_agg_proofs.lhs.is_agg,
            expanded_agg_proofs.lhs.intern,
            expanded_agg_proofs.rhs.is_agg,
            expanded_agg_proofs.rhs.intern,
            expanded_agg_proofs.p_vals,
        )
        .map_err(|err| err.to_string())?;

    let common = ProofCommon {
        b_height: lhs_child.b_height(),
        deltas,
        roots_before: p_vals.trie_roots_before,
        roots_after: p_vals.trie_roots_after,
    };

    Ok(GeneratedAggProof {
        common,
        underlying_txns: lhs_child
            .underlying_txns()
            .combine(&rhs_child.underlying_txns()),
        intern: agg_proof_intern,
    })
}

struct ExpandedAggregatableProofs<'a> {
    p_vals: PublicValues,
    lhs: ExpandedAggregatableProof<'a>,
    rhs: ExpandedAggregatableProof<'a>,
}

struct ExpandedAggregatableProof<'a> {
    intern: &'a PlonkyProofIntern,
    is_agg: bool,
}

fn expand_aggregatable_proofs<'a>(
    lhs_child: &'a AggregatableProof,
    rhs_child: &'a AggregatableProof,
    b_data: BlockLevelData,
) -> ExpandedAggregatableProofs<'a> {
    let (expanded_lhs, lhs_common) = expand_aggregatable_proof(lhs_child);
    let (expanded_rhs, rhs_common) = expand_aggregatable_proof(rhs_child);

    let txn_idxs = lhs_child
        .underlying_txns()
        .combine(&rhs_child.underlying_txns());
    let deltas = merge_lhs_and_rhs_deltas(&lhs_common.deltas, &rhs_common.deltas);
    let extra_block_data =
        deltas.into_extra_block_data(txn_idxs.txn_idxs.start, txn_idxs.txn_idxs.end);

    let p_vals = PublicValues {
        trie_roots_before: lhs_common.roots_before.clone(),
        trie_roots_after: rhs_common.roots_after.clone(),
        block_metadata: b_data.b_meta,
        block_hashes: b_data.b_hashes,
        extra_block_data,
    };

    ExpandedAggregatableProofs {
        p_vals,
        lhs: expanded_lhs,
        rhs: expanded_rhs,
    }
}

fn merge_lhs_and_rhs_deltas(
    lhs: &ProofBeforeAndAfterDeltas,
    rhs: &ProofBeforeAndAfterDeltas,
) -> ProofBeforeAndAfterDeltas {
    ProofBeforeAndAfterDeltas {
        gas_used_before: lhs.gas_used_before,
        gas_used_after: rhs.gas_used_after,
        block_bloom_before: lhs.block_bloom_before,
        block_bloom_after: rhs.block_bloom_after,
    }
}

fn expand_aggregatable_proof(p: &AggregatableProof) -> (ExpandedAggregatableProof, &ProofCommon) {
    let (intern, is_agg, common) = match p {
        AggregatableProof::Txn(txn_intern) => (&txn_intern.intern, false, &txn_intern.common),
        AggregatableProof::Agg(agg_intern) => (&agg_intern.intern, true, &agg_intern.common),
    };

    let expanded = ExpandedAggregatableProof { intern, is_agg };

    (expanded, common)
}

pub fn generate_block_proof(
    p_state: &ProverState,
    prev_opt_parent_b_proof: Option<&GeneratedBlockProof>,
    curr_block_agg_proof: &GeneratedAggProof,
    b_data: BlockLevelData,
) -> ProofGenResult<GeneratedBlockProof> {
    let b_height = curr_block_agg_proof.common.b_height;
    let parent_intern = prev_opt_parent_b_proof.map(|p| &p.intern);

    let p_vals = PublicValues {
        trie_roots_before: curr_block_agg_proof.common.roots_before.clone(),
        trie_roots_after: curr_block_agg_proof.common.roots_after.clone(),
        block_metadata: b_data.b_meta,
        block_hashes: b_data.b_hashes,
        extra_block_data: curr_block_agg_proof
            .common
            .deltas
            .clone()
            .into_extra_block_data(0, curr_block_agg_proof.underlying_txns.txn_idxs.end),
    };

    let (b_proof_intern, _) = p_state
        .state
        .prove_block(parent_intern, &curr_block_agg_proof.intern, p_vals)
        .map_err(|err| err.to_string())?;

    Ok(GeneratedBlockProof {
        b_height,
        intern: b_proof_intern,
    })
}