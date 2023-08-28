#![no_main]

use itertools::Itertools;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::mem;

use crate::mock::{
    balance_hold, roll_to, round_down, total_balance, AccountId, Balance, Balances,
    ExistentialDeposit, ExtBuilder, Runtime, RuntimeOrigin, Staking, State, ACCOUNT_STAKING,
    DEFAULT_BALANCE, MEGA,
};
use frame_support::assert_err;
use frame_support::assert_ok;
use pallet_pooled_staking::candidate::Candidates;
use pallet_pooled_staking::pools::check_candidate_consistency;
use pallet_pooled_staking::pools::Pool;
use pallet_pooled_staking::AllTargetPool;
use pallet_pooled_staking::PendingOperationKey;
use pallet_pooled_staking::PendingOperationQuery;
use pallet_pooled_staking::PendingOperations;
use pallet_pooled_staking::Pools;
use pallet_pooled_staking::PoolsKey;
use pallet_pooled_staking::SharesOrStake;
use pallet_pooled_staking::SortedEligibleCandidates;
use pallet_pooled_staking::TargetPool;

mod mock;
mod tests;

#[derive(Arbitrary, Debug)]
struct FuzzData {
    config: FuzzConfig,
    xts: Vec<FuzzExtrinsic>,
}

#[derive(Arbitrary, Debug)]
struct FuzzConfig {
    //num_with_balance: u32,
}

impl FuzzConfig {
    fn valid(&self) -> bool {
        //self.num_with_balance < 100
        true
    }

    fn balances(&self) -> Vec<(AccountId, Balance)> {
        let mut b = vec![];

        //for i in 0..self.num_with_balance {
        for i in 0..20 {
            b.push((i as u64, DEFAULT_BALANCE));
        }

        b
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzBlock {
    xts: Vec<FuzzExtrinsic>,
}

#[derive(Clone, Arbitrary, Debug)]
enum FuzzExtrinsic {
    NewBlock,
    Join {
        candidate: FuzzAccountId,
        delegator: FuzzAccountId,
        pool: FuzzTargetPool,
        amount: Balance,
    },
    Leave {
        candidate: FuzzAccountId,
        delegator: FuzzAccountId,
        pool: FuzzTargetPool,
        amount: Balance,
    },
    ExecutePending {
        operations: Vec<FuzzPendingOperationQuery>,
    },
    RebalanceHold {
        candidate: FuzzAccountId,
        delegator: FuzzAccountId,
        pool: FuzzAllTargetPool,
    },

    // Smart operations
    ExecutePendingByIndex {
        i: u8,
    },
    LeaveFullAmount {
        candidate: FuzzAccountId,
        delegator: FuzzAccountId,
        pool: FuzzTargetPool,
    },
    JoinFullAmount {
        candidate: FuzzAccountId,
        delegator: FuzzAccountId,
        pool: FuzzTargetPool,
    },
    LeaveShares {
        candidate: FuzzAccountId,
        delegator: FuzzAccountId,
        pool: FuzzTargetPool,
        shares: u128,
    },
    LeavePool {
        delegator: FuzzAccountId,
        pool: FuzzTargetPool,
    },
    ExecuteAllPending,
    EmptyPool {
        pool: FuzzTargetPool,
    },
}

#[derive(Clone, Arbitrary, Debug)]
struct FuzzPendingOperationQuery {
    delegator: FuzzAccountId,
    operation: FuzzPendingOperationKey<FuzzAccountId, u8>,
}

#[derive(Clone, Arbitrary, Debug)]
enum FuzzPendingOperationKey<A, B> {
    /// Candidate requested to join the auto compounding pool of a candidate.
    JoiningAutoCompounding { candidate: A, at_block: B },
    /// Candidate requested to join the manual rewards pool of a candidate.
    JoiningManualRewards { candidate: A, at_block: B },
    /// Candidate requested to to leave a pool of a candidate.
    Leaving { candidate: A, at_block: B },
}

fn fix_block_number(this: &mut PendingOperationKey<u64, u64>, block_number: u64) {
    match this {
        PendingOperationKey::JoiningAutoCompounding {
            candidate,
            at_block,
        } => *at_block = block_number.saturating_sub(*at_block),
        PendingOperationKey::JoiningManualRewards {
            candidate,
            at_block,
        } => *at_block = block_number.saturating_sub(*at_block),
        PendingOperationKey::Leaving {
            candidate,
            at_block,
        } => *at_block = block_number.saturating_sub(*at_block),
    }
}

impl From<FuzzPendingOperationKey<FuzzAccountId, u8>> for PendingOperationKey<u64, u64> {
    fn from(x: FuzzPendingOperationKey<FuzzAccountId, u8>) -> PendingOperationKey<u64, u64> {
        match x {
            FuzzPendingOperationKey::JoiningAutoCompounding {
                candidate,
                at_block,
            } => PendingOperationKey::JoiningAutoCompounding {
                candidate: candidate.into(),
                at_block: at_block.into(),
            },
            FuzzPendingOperationKey::JoiningManualRewards {
                candidate,
                at_block,
            } => PendingOperationKey::JoiningManualRewards {
                candidate: candidate.into(),
                at_block: at_block.into(),
            },
            FuzzPendingOperationKey::Leaving {
                candidate,
                at_block,
            } => PendingOperationKey::Leaving {
                candidate: candidate.into(),
                at_block: at_block.into(),
            },
        }
    }
}

#[derive(Clone, Arbitrary, Debug)]
struct FuzzAccountId(u8);

impl FuzzAccountId {
    fn valid(&self) -> bool {
        //self.0 <= 5
        true
    }
}

impl From<FuzzAccountId> for AccountId {
    fn from(x: FuzzAccountId) -> AccountId {
        x.0.into()
    }
}

#[derive(Clone, Arbitrary, Debug)]
enum FuzzTargetPool {
    AutoCompounding,
    ManualRewards,
}

impl From<FuzzTargetPool> for TargetPool {
    fn from(x: FuzzTargetPool) -> TargetPool {
        match x {
            FuzzTargetPool::AutoCompounding => TargetPool::AutoCompounding,
            FuzzTargetPool::ManualRewards => TargetPool::ManualRewards,
        }
    }
}

#[derive(Clone, Arbitrary, Debug)]
enum FuzzAllTargetPool {
    Joining,
    AutoCompounding,
    ManualRewards,
    Leaving,
}

impl From<FuzzAllTargetPool> for AllTargetPool {
    fn from(x: FuzzAllTargetPool) -> AllTargetPool {
        match x {
            FuzzAllTargetPool::Joining => AllTargetPool::Joining,
            FuzzAllTargetPool::AutoCompounding => AllTargetPool::AutoCompounding,
            FuzzAllTargetPool::ManualRewards => AllTargetPool::ManualRewards,
            FuzzAllTargetPool::Leaving => AllTargetPool::Leaving,
        }
    }
}

impl FuzzExtrinsic {
    fn execute(self, block_number: u64) {
        let log_msg = format!("{:?}", self);
        let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();
        eprintln!("{:?}", storage_pools);
        eprintln!("execute {}", log_msg);
        match self {
            FuzzExtrinsic::NewBlock => {
                // Handled in main loop
            }

            FuzzExtrinsic::Join {
                candidate,
                delegator,
                pool,
                amount,
            } => {
                if amount == 0 {
                    assert_err!(
                        Staking::request_delegate(
                            RuntimeOrigin::signed(delegator.into()),
                            candidate.into(),
                            pool.into(),
                            amount,
                        ),
                        pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                    );
                    return;
                }

                // Check that candidate is in pool
                let candidate = candidate.into();

                /*
                let shares = match &pool {
                    FuzzTargetPool::ManualRewards => {
                        pallet_pooled_staking::pools::ManualRewards::<Runtime>::stake_to_shares_or_init(&candidate, pallet_pooled_staking::Stake(amount)).unwrap().0
                    }
                    FuzzTargetPool::AutoCompounding => {
                        pallet_pooled_staking::pools::AutoCompounding::<Runtime>::stake_to_shares_or_init(&candidate, pallet_pooled_staking::Stake(amount)).unwrap().0
                    }
                };
                */
                let shares =
                    pallet_pooled_staking::pools::Joining::<Runtime>::stake_to_shares_or_init(
                        &candidate,
                        pallet_pooled_staking::Stake(amount),
                    )
                    .unwrap()
                    .0;
                if shares == 0 {
                    assert_err!(
                        Staking::request_delegate(
                            RuntimeOrigin::signed(delegator.into()),
                            candidate.into(),
                            pool.into(),
                            amount,
                        ),
                        pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                    );
                    return;
                }

                //let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();
                if <Runtime as pallet_pooled_staking::Config>::Currency::free_balance(
                    &delegator.clone().into(),
                ) + ExistentialDeposit::get()
                    <= amount
                {
                    let err = Staking::request_delegate(
                        RuntimeOrigin::signed(delegator.into()),
                        candidate.into(),
                        pool.into(),
                        amount,
                    )
                    .unwrap_err();

                    if err == sp_runtime::TokenError::CannotCreateHold.into() {
                    } else if err == sp_runtime::TokenError::FundsUnavailable.into() {
                    } else if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {
                    } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {
                    } else {
                        panic!("{:?}", err);
                    }
                    return;
                }

                //eprintln!("{:?}", storage_pools);
                //eprintln!("valid join: {}", log_msg);
                tests::do_request_delegation(
                    candidate,
                    delegator.into(),
                    pool.into(),
                    amount,
                    round_down(amount, 2),
                );
            }

            FuzzExtrinsic::Leave {
                candidate,
                delegator,
                pool,
                amount,
            } => {
                let candidate = candidate.into();

                if amount == 0 {
                    let err = Staking::request_undelegate(
                        RuntimeOrigin::signed(delegator.clone().into()),
                        candidate,
                        pool.clone().into(),
                        SharesOrStake::Stake(amount.into()),
                    )
                    .unwrap_err();
                    if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {
                    } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into()
                    {
                    } else {
                        panic!("{:?}", err);
                    }
                    return;
                }

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        let total_staked = Pools::<Runtime>::get(
                            candidate,
                            PoolsKey::AutoCompoundingSharesHeldStake {
                                delegator: delegator.clone().into(),
                            },
                        );
                        if total_staked == 0 {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.clone().into()),
                                candidate,
                                pool.clone().into(),
                                SharesOrStake::Stake(amount.into()),
                            )
                            .unwrap_err();
                            if err
                                == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                                    .into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                            return;
                        }

                        let num_shares = pallet_pooled_staking::pools::AutoCompounding::<Runtime>::stake_to_shares(&candidate, pallet_pooled_staking::Stake(amount.into())).map(|x| x.0).unwrap_or(0);
                        if num_shares == 0 {
                            assert_err!(
                                Staking::request_undelegate(
                                    RuntimeOrigin::signed(delegator.into()),
                                    candidate,
                                    pool.into(),
                                    SharesOrStake::Stake(amount.into()),
                                ),
                                pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                            );
                            return;
                        }

                        if amount > total_staked {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Stake(amount.into()),
                            )
                            .unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                        } else {
                            assert_ok!(Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Stake(amount.into()),
                            ));
                        }
                        return;
                    }
                    FuzzTargetPool::ManualRewards => {
                        let total_staked = Pools::<Runtime>::get(
                            candidate,
                            PoolsKey::ManualRewardsSharesHeldStake {
                                delegator: delegator.clone().into(),
                            },
                        );
                        if total_staked == 0 {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.clone().into()),
                                candidate,
                                pool.clone().into(),
                                SharesOrStake::Stake(amount.into()),
                            )
                            .unwrap_err();
                            if err
                                == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                                    .into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                            return;
                        }

                        let num_shares = pallet_pooled_staking::pools::ManualRewards::<Runtime>::stake_to_shares(&candidate, pallet_pooled_staking::Stake(amount.into())).map(|x| x.0).unwrap_or(0);
                        if num_shares == 0 {
                            assert_err!(
                                Staking::request_undelegate(
                                    RuntimeOrigin::signed(delegator.into()),
                                    candidate,
                                    pool.into(),
                                    SharesOrStake::Stake(amount.into()),
                                ),
                                pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                            );
                            return;
                        }

                        if amount > total_staked {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Stake(amount.into()),
                            )
                            .unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                        } else {
                            assert_ok!(Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Stake(amount.into()),
                            ));
                        }
                        return;
                    }
                }
            }

            FuzzExtrinsic::ExecutePending { operations } => {
                for mut op in operations {
                    //eprintln!("valid execute pending: {}", log_msg);

                    let mut oper = op.operation.into();
                    fix_block_number(&mut oper, block_number);
                    // Not using assert_ok because this can return
                    // RequestCannotBeExecuted error
                    // TODO: check error conditions
                    let _ = Staking::execute_pending_operations(
                        RuntimeOrigin::signed(0),
                        vec![PendingOperationQuery {
                            delegator: op.delegator.into(),
                            operation: oper,
                        }],
                    );
                }
            }

            FuzzExtrinsic::RebalanceHold {
                candidate,
                delegator,
                pool,
            } => {
                let storage_pools: Vec<_> = Pools::<Runtime>::iter()
                    .filter(|(candidate1, _key, _amount)| {
                        *candidate1 == AccountId::from(candidate.clone())
                    })
                    .collect();
                // Handle empty pools
                if storage_pools.is_empty() {
                    assert_err!(
                        Staking::rebalance_hold(
                            RuntimeOrigin::signed(0),
                            candidate.into(),
                            delegator.into(),
                            pool.into(),
                        ),
                        pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking
                    );
                    return;
                }

                // Check that the target pool is not empty
                match &pool {
                    FuzzAllTargetPool::Joining => {
                        let pool_total_stake = storage_pools
                            .iter()
                            .filter_map(|(_candidate, key, amount)| match key {
                                PoolsKey::JoiningSharesTotalStaked => Some(*amount),
                                _ => None,
                            })
                            .next()
                            .unwrap_or(0);

                        if pool_total_stake == 0 {
                            assert_err!(
                                Staking::rebalance_hold(
                                    RuntimeOrigin::signed(0),
                                    candidate.into(),
                                    delegator.into(),
                                    pool.into(),
                                ),
                                pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking
                            );
                            return;
                        }
                    }
                    FuzzAllTargetPool::AutoCompounding => {
                        let pool_total_stake = storage_pools
                            .iter()
                            .filter_map(|(_candidate, key, amount)| match key {
                                PoolsKey::AutoCompoundingSharesTotalStaked => Some(*amount),
                                _ => None,
                            })
                            .next()
                            .unwrap_or(0);

                        if pool_total_stake == 0 {
                            assert_err!(
                                Staking::rebalance_hold(
                                    RuntimeOrigin::signed(0),
                                    candidate.into(),
                                    delegator.into(),
                                    pool.into(),
                                ),
                                pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking
                            );
                            return;
                        }
                    }
                    FuzzAllTargetPool::ManualRewards => {
                        let pool_total_stake = storage_pools
                            .iter()
                            .filter_map(|(_candidate, key, amount)| match key {
                                PoolsKey::ManualRewardsSharesTotalStaked => Some(*amount),
                                _ => None,
                            })
                            .next()
                            .unwrap_or(0);

                        if pool_total_stake == 0 {
                            assert_err!(
                                Staking::rebalance_hold(
                                    RuntimeOrigin::signed(0),
                                    candidate.into(),
                                    delegator.into(),
                                    pool.into(),
                                ),
                                pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking
                            );
                            return;
                        }
                    }
                    FuzzAllTargetPool::Leaving => {
                        let pool_total_stake = storage_pools
                            .iter()
                            .filter_map(|(_candidate, key, amount)| match key {
                                PoolsKey::LeavingSharesTotalStaked => Some(*amount),
                                _ => None,
                            })
                            .next()
                            .unwrap_or(0);

                        if pool_total_stake == 0 {
                            assert_err!(
                                Staking::rebalance_hold(
                                    RuntimeOrigin::signed(0),
                                    candidate.into(),
                                    delegator.into(),
                                    pool.into(),
                                ),
                                pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking
                            );
                            return;
                        }
                    }
                }

                assert_ok!(Staking::rebalance_hold(
                    RuntimeOrigin::signed(0),
                    candidate.into(),
                    delegator.into(),
                    pool.into(),
                ));
            }

            FuzzExtrinsic::ExecutePendingByIndex { i } => {
                let op = PendingOperations::<Runtime>::iter().skip(i as usize).next();

                if op.is_none() {
                    return;
                }

                let op = op.unwrap();

                let (delegator, key, _amount) = op;

                // Not using assert_ok because this can return
                // RequestCannotBeExecuted error
                // TODO: check error conditions
                let _ = Staking::execute_pending_operations(
                    RuntimeOrigin::signed(0),
                    vec![PendingOperationQuery {
                        delegator: delegator,
                        operation: key,
                    }],
                );
            }

            FuzzExtrinsic::LeaveFullAmount {
                candidate,
                delegator,
                pool,
            } => {
                // Check that candidate is in pool
                let candidate = candidate.into();

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        let total_staked = Pools::<Runtime>::get(
                            candidate,
                            PoolsKey::AutoCompoundingSharesHeldStake {
                                delegator: delegator.clone().into(),
                            },
                        );
                        if total_staked == 0 {
                            let amount = 1u8;
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.clone().into()),
                                candidate,
                                pool.clone().into(),
                                SharesOrStake::Stake(amount.into()),
                            )
                            .unwrap_err();
                            if err
                                == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                                    .into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                            return;
                        }
                        let amount = total_staked;
                        assert_ok!(Staking::request_undelegate(
                            RuntimeOrigin::signed(delegator.into()),
                            candidate,
                            pool.into(),
                            SharesOrStake::Stake(amount.into()),
                        ));
                        return;
                    }
                    FuzzTargetPool::ManualRewards => {
                        let total_staked = Pools::<Runtime>::get(
                            candidate,
                            PoolsKey::ManualRewardsSharesHeldStake {
                                delegator: delegator.clone().into(),
                            },
                        );
                        if total_staked == 0 {
                            let amount = 1u8;
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.clone().into()),
                                candidate,
                                pool.clone().into(),
                                SharesOrStake::Stake(amount.into()),
                            )
                            .unwrap_err();
                            if err
                                == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                                    .into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                            return;
                        }
                        let amount = total_staked;
                        assert_ok!(Staking::request_undelegate(
                            RuntimeOrigin::signed(delegator.into()),
                            candidate,
                            pool.into(),
                            SharesOrStake::Stake(amount.into()),
                        ));
                        return;
                    }
                }
            }

            FuzzExtrinsic::JoinFullAmount {
                candidate,
                delegator,
                pool,
            } => {
                let amount = <Runtime as pallet_pooled_staking::Config>::Currency::free_balance(
                    &delegator.clone().into(),
                )
                .saturating_sub(ExistentialDeposit::get());
                let min_amount = 10 * MEGA;
                if amount < min_amount {
                    return;
                }

                tests::do_request_delegation(
                    candidate.into(),
                    delegator.into(),
                    pool.into(),
                    amount,
                    round_down(amount, 2),
                );
            }

            FuzzExtrinsic::LeaveShares {
                candidate,
                delegator,
                pool,
                shares,
            } => {
                let candidate = candidate.into();

                if shares == 0 {
                    let err = Staking::request_undelegate(
                        RuntimeOrigin::signed(delegator.clone().into()),
                        candidate,
                        pool.clone().into(),
                        SharesOrStake::Shares(shares.into()),
                    )
                    .unwrap_err();
                    if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {
                    } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into()
                    {
                    } else {
                        panic!("{:?}", err);
                    }
                    return;
                }

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        let total_staked = Pools::<Runtime>::get(
                            candidate,
                            PoolsKey::AutoCompoundingSharesHeldStake {
                                delegator: delegator.clone().into(),
                            },
                        );
                        if total_staked == 0 {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.clone().into()),
                                candidate,
                                pool.clone().into(),
                                SharesOrStake::Shares(shares.into()),
                            )
                            .unwrap_err();
                            if err
                                == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                                    .into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                            return;
                        }
                        let amount = total_staked;
                        let shares_amount = pallet_pooled_staking::pools::AutoCompounding::<Runtime>::shares_to_stake(&candidate, pallet_pooled_staking::Shares(shares.into())).map(|x| x.0).unwrap_or(u128::MAX);

                        if shares_amount > amount {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Shares(shares.into()),
                            )
                            .unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                        } else {
                            assert_ok!(Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Shares(shares.into()),
                            ));
                        }
                        return;
                    }
                    FuzzTargetPool::ManualRewards => {
                        let total_staked = Pools::<Runtime>::get(
                            candidate,
                            PoolsKey::ManualRewardsSharesHeldStake {
                                delegator: delegator.clone().into(),
                            },
                        );
                        if total_staked == 0 {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.clone().into()),
                                candidate,
                                pool.clone().into(),
                                SharesOrStake::Shares(shares.into()),
                            )
                            .unwrap_err();
                            if err
                                == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero
                                    .into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into()
                            {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                            return;
                        }
                        let amount = total_staked;
                        let shares_amount = pallet_pooled_staking::pools::ManualRewards::<Runtime>::shares_to_stake(&candidate, pallet_pooled_staking::Shares(shares.into())).map(|x| x.0).unwrap_or(u128::MAX);

                        if shares_amount > amount {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Shares(shares.into()),
                            )
                            .unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {
                            } else if err
                                == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into()
                            {
                            } else {
                                panic!("{:?}", err);
                            }
                        } else {
                            assert_ok!(Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Shares(shares.into()),
                            ));
                        }
                        return;
                    }
                }
            }

            FuzzExtrinsic::LeavePool { delegator, pool } => {
                let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        for (candidate, key, amount) in storage_pools {
                            if let PoolsKey::AutoCompoundingSharesHeldStake {
                                delegator: delegator1,
                            } = key
                            {
                                if delegator1 == AccountId::from(delegator.clone()) {
                                    FuzzExtrinsic::LeaveFullAmount {
                                        candidate: FuzzAccountId(candidate as u8),
                                        delegator: delegator.clone(),
                                        pool: pool.clone(),
                                    }
                                    .execute(block_number);
                                }
                            }
                        }
                    }
                    FuzzTargetPool::ManualRewards => {
                        for (candidate, key, amount) in storage_pools {
                            if let PoolsKey::ManualRewardsSharesHeldStake {
                                delegator: delegator1,
                            } = key
                            {
                                if delegator1 == AccountId::from(delegator.clone()) {
                                    FuzzExtrinsic::LeaveFullAmount {
                                        candidate: FuzzAccountId(candidate as u8),
                                        delegator: delegator.clone(),
                                        pool: pool.clone(),
                                    }
                                    .execute(block_number);
                                }
                            }
                        }
                    }
                }
            }

            FuzzExtrinsic::ExecuteAllPending => {
                let ops: Vec<_> = PendingOperations::<Runtime>::iter().collect();

                // Execute each op in a separate extrinsic, because if we try to execute them all
                // at once, if one fails then no progress will be made
                for op in ops {
                    let (delegator, key, _amount) = op;

                    // Not using assert_ok because this can return
                    // RequestCannotBeExecuted error
                    // TODO: check error conditions
                    let _ = Staking::execute_pending_operations(
                        RuntimeOrigin::signed(0),
                        vec![PendingOperationQuery {
                            delegator: delegator,
                            operation: key,
                        }],
                    );
                }
            }

            FuzzExtrinsic::EmptyPool { pool } => {
                let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        for (candidate, key, amount) in storage_pools {
                            if let PoolsKey::AutoCompoundingSharesHeldStake {
                                delegator: delegator1,
                            } = key
                            {
                                FuzzExtrinsic::LeavePool {
                                    delegator: FuzzAccountId(delegator1 as u8),
                                    pool: pool.clone(),
                                }
                                .execute(block_number);
                            }
                        }
                    }
                    FuzzTargetPool::ManualRewards => {
                        for (candidate, key, amount) in storage_pools {
                            if let PoolsKey::ManualRewardsSharesHeldStake {
                                delegator: delegator1,
                            } = key
                            {
                                FuzzExtrinsic::LeavePool {
                                    delegator: FuzzAccountId(delegator1 as u8),
                                    pool: pool.clone(),
                                }
                                .execute(block_number);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn fuzz_main(data: FuzzData) {
    // Ensure valid config
    if !data.config.valid() {
        return;
    }

    // Limit number of extrinsics
    if data.xts.len() > 200 {
        return;
    }

    // Separate extrinsics into blocks
    let mut blocks = vec![];
    let mut curr_block = vec![];

    for xt in data.xts {
        if let FuzzExtrinsic::NewBlock = &xt {
            blocks.push(mem::take(&mut curr_block));

            // Limit number of blocks
            if blocks.len() > 100 {
                return;
            }
        } else {
            curr_block.push(xt);
        }
    }

    blocks.push(curr_block);

    let balances = data.config.balances();
    ExtBuilder::default()
        .with_balances(balances)
        .build()
        .execute_with(|| {
            let expected_total_issuance = Balances::total_issuance();
            let last_block_number = blocks.len() as u64;
            //eprintln!("starting new test");
            for (block_number, block) in blocks.into_iter().enumerate() {
                // Start at block 1
                let block_number: u64 = (block_number + 1) as u64;
                //eprintln!("enter block {}", block_number);
                roll_to(block_number);

                for xt in block {
                    xt.execute(block_number);
                }

                // Assertions
                /*
                // Total stake is correct
                // TODO: this is too slow, check existing candidates instead of u8::MAX
                for candidate in 0..=u8::MAX {
                    if let Err(e) = check_candidate_consistency::<Runtime>(&candidate.into()) {
                        panic!("candidate {} inconsistent: {:?}", candidate, e);
                    }
                }
                */

                // Sorted lists are sorted
                assert!(is_sorted(&SortedEligibleCandidates::<Runtime>::get()));

                // Nothing is burned
                assert_eq!(Balances::total_issuance(), expected_total_issuance);
            }

            let block_number = last_block_number + 1;
            roll_to(block_number);

            // Post test: empty all pools and check that balances match original ones
            // First, execute all pending to empty the Joining pool
            // Otherwise, the candidates in Joining pool are eligible
            // Wait 10 blocks so we can execute
            let block_number = block_number + 10;
            roll_to(block_number);
            FuzzExtrinsic::ExecuteAllPending.execute(block_number);
            FuzzExtrinsic::EmptyPool {
                pool: FuzzTargetPool::AutoCompounding,
            }
            .execute(block_number);
            FuzzExtrinsic::EmptyPool {
                pool: FuzzTargetPool::ManualRewards,
            }
            .execute(block_number);
            // Now all candidates are in leaving pool, so no one is eligible
            assert_eq!(SortedEligibleCandidates::<Runtime>::get(), vec![]);
            // Wait 10 blocks so we can execute
            let block_number = block_number + 10;
            roll_to(block_number);
            FuzzExtrinsic::ExecuteAllPending.execute(block_number);

            // No candidates
            assert_eq!(SortedEligibleCandidates::<Runtime>::get(), vec![]);
            // Nothing is burned
            assert_eq!(Balances::total_issuance(), expected_total_issuance);
            // Check balances
            let staking_balance = total_balance(&ACCOUNT_STAKING);
            assert_eq!(staking_balance, DEFAULT_BALANCE);

            for account in 0..20 {
                let account = account as u64;
                if account == ACCOUNT_STAKING {
                    continue;
                }
                let delegator_balance = total_balance(&account);
                let delegator_hold = balance_hold(&account);
                let candidate_total_stake = Candidates::<Runtime>::total_stake(&account).0;

                assert_eq!(delegator_balance, DEFAULT_BALANCE);
                assert_eq!(delegator_hold, 0);
                assert_eq!(candidate_total_stake, 0);
            }

            // TODO: this fails
            // Pallet staking storage is now empty
            //let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();
            //assert_eq!(storage_pools, vec![]);
            //eprintln!("ending test");
        });
}

fuzz_target!(|data: FuzzData| { fuzz_main(data) });

// https://stackoverflow.com/a/51272639
fn is_sorted<T>(data: &[T]) -> bool
where
    T: Ord,
{
    data.windows(2).all(|w| w[0] <= w[1])
}
