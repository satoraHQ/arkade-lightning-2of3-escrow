use anyhow::{Context, Result, ensure};
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
    pub buyer_amount: Amount,
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
    let buyer_amount = total_escrow_amount.checked_sub(total_fee).with_context(|| {
        format!("fee exceeds amount locked up in escrow contract: {total_fee} > {total_escrow_amount}")
    })?;

    ensure!(
        buyer_amount >= dust,
        "server dust ({dust}) exceeds buyer payout ({buyer_amount})",
    );

    Ok(ReleasePlan {
        total_escrow_amount,
        buyer_amount,
        effective_fee_outputs,
        discarded_fee_outputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUST: Amount = Amount::from_sat(330);

    #[test]
    fn plan_release_rejects_sub_dust_buyer_payout() {
        let err = plan_release(Amount::from_sat(300), &[], ReleaseMode::Offchain, DUST)
            .unwrap_err()
            .to_string();

        assert!(err.contains("exceeds buyer payout"), "{err}");
    }

    #[test]
    fn plan_release_accepts_buyer_payout_at_dust() {
        let plan = plan_release(DUST, &[], ReleaseMode::Offchain, DUST).unwrap();

        assert_eq!(plan.buyer_amount, DUST);
    }
}
