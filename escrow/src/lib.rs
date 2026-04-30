use anyhow::{Context, Result};
use bitcoin::Amount;

pub mod client;
pub mod contract;
pub mod delegate;
pub mod refresh;
pub mod spend;
pub mod spend_store;

#[derive(Clone, Copy, Debug)]
pub struct FeeOutput {
    pub address: ark_core::ArkAddress,
    pub amount: Amount,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseMode {
    Offchain,
    Delegate,
}

#[derive(Clone, Debug)]
pub struct ReleasePlan {
    pub total_escrow_amount: Amount,
    pub bob_amount: Amount,
    pub effective_fee_outputs: Vec<FeeOutput>,
    pub discarded_fee_outputs: Vec<FeeOutput>,
}

pub fn plan_release(
    total_escrow_amount: Amount,
    fee_outputs: &[FeeOutput],
    mode: ReleaseMode,
    dust: Amount,
) -> Result<ReleasePlan> {
    let (discarded_fee_outputs, effective_fee_outputs): (Vec<_>, Vec<_>) = match mode {
        ReleaseMode::Offchain => (Vec::new(), fee_outputs.to_vec()),
        ReleaseMode::Delegate => fee_outputs.iter().copied().partition(|o| o.amount < dust),
    };

    let total_fee: Amount = effective_fee_outputs.iter().map(|o| o.amount).sum();
    let bob_amount = total_escrow_amount.checked_sub(total_fee).with_context(|| {
        format!("fee exceeds amount locked up in escrow contract: {total_fee} > {total_escrow_amount}")
    })?;

    Ok(ReleasePlan {
        total_escrow_amount,
        bob_amount,
        effective_fee_outputs,
        discarded_fee_outputs,
    })
}
