#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use itertools::Itertools;
use std::mem;

use crate::mock::{AccountId, Balance, Balances, roll_to, ExtBuilder, Runtime, RuntimeOrigin, Staking, MEGA, DEFAULT_BALANCE, round_down, ExistentialDeposit, State, total_balance, ACCOUNT_STAKING, balance_hold};
use pallet_pooled_staking::AllTargetPool;
use pallet_pooled_staking::Pools;
use pallet_pooled_staking::pools::Pool;
use pallet_pooled_staking::TargetPool;
use pallet_pooled_staking::candidate::Candidates;
use pallet_pooled_staking::PendingOperationQuery;
use pallet_pooled_staking::PendingOperationKey;
use pallet_pooled_staking::SharesOrStake;
use pallet_pooled_staking::PendingOperations;
use pallet_pooled_staking::SortedEligibleCandidates;
use pallet_pooled_staking::PoolsKey;
use pallet_pooled_staking::pools::check_candidate_consistency;
use frame_support::assert_ok;
use frame_support::assert_err;

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
        PendingOperationKey::JoiningAutoCompounding { candidate, at_block } => *at_block = block_number.saturating_sub(*at_block),
        PendingOperationKey::JoiningManualRewards { candidate, at_block } => *at_block = block_number.saturating_sub(*at_block),
        PendingOperationKey::Leaving { candidate, at_block } => *at_block = block_number.saturating_sub(*at_block),
    }
}

impl From<FuzzPendingOperationKey<FuzzAccountId, u8>> for PendingOperationKey<u64, u64> {
    fn from(x: FuzzPendingOperationKey<FuzzAccountId, u8>) -> PendingOperationKey<u64, u64> {
        match x {
            FuzzPendingOperationKey::JoiningAutoCompounding { candidate, at_block } => PendingOperationKey::JoiningAutoCompounding { candidate: candidate.into(), at_block: at_block.into() },
            FuzzPendingOperationKey::JoiningManualRewards { candidate, at_block } => PendingOperationKey::JoiningManualRewards { candidate: candidate.into(), at_block: at_block.into() },
            FuzzPendingOperationKey::Leaving { candidate, at_block } => PendingOperationKey::Leaving { candidate: candidate.into(), at_block: at_block.into() },
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
                    assert_err!(Staking::request_delegate(
                        RuntimeOrigin::signed(delegator.into()),
                        candidate.into(),
                        pool.into(),
                        amount,
                    ), pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero);
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
                let shares = pallet_pooled_staking::pools::Joining::<Runtime>::stake_to_shares_or_init(&candidate, pallet_pooled_staking::Stake(amount)).unwrap().0;
                if shares == 0 {
                    assert_err!(Staking::request_delegate(
                        RuntimeOrigin::signed(delegator.into()),
                        candidate.into(),
                        pool.into(),
                        amount,
                    ), pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero);
                    return;
                }

                //let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();
                if <Runtime as pallet_pooled_staking::Config>::Currency::free_balance(&delegator.clone().into()) + ExistentialDeposit::get() <= amount {
                    let err = Staking::request_delegate(
                        RuntimeOrigin::signed(delegator.into()),
                        candidate.into(),
                        pool.into(),
                        amount,
                    ).unwrap_err();

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
                tests::do_request_delegation(candidate, delegator.into(), pool.into(), amount, round_down(amount, 2));
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
                        ).unwrap_err();
                    if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {

                    } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into() {

                    } else {
                        panic!("{:?}", err);
                    }
                    return;
                }

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        let total_staked = Pools::<Runtime>::get(candidate, PoolsKey::AutoCompoundingSharesHeldStake { delegator: delegator.clone().into() });
                        if total_staked == 0 {
                            let err = Staking::request_undelegate(
                                    RuntimeOrigin::signed(delegator.clone().into()),
                                    candidate,
                                    pool.clone().into(),
                                    SharesOrStake::Stake(amount.into()),
                                ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {

                            } else {
                                panic!("{:?}", err);
                            }
                            return;
                        }

                        let num_shares = pallet_pooled_staking::pools::AutoCompounding::<Runtime>::stake_to_shares(&candidate, pallet_pooled_staking::Stake(amount.into())).map(|x| x.0).unwrap_or(0);
                        if num_shares == 0 {
                            assert_err!(Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Stake(amount.into()),
                            ), pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero);
                            return;
                        }

                        if amount > total_staked {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Stake(amount.into()),
                            ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {

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
                        let total_staked = Pools::<Runtime>::get(candidate, PoolsKey::ManualRewardsSharesHeldStake { delegator: delegator.clone().into() });
                        if total_staked == 0 {
                            let err = Staking::request_undelegate(
                                    RuntimeOrigin::signed(delegator.clone().into()),
                                    candidate,
                                    pool.clone().into(),
                                    SharesOrStake::Stake(amount.into()),
                                ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {

                            } else {
                                panic!("{:?}", err);
                            }
                            return;
                        }

                        let num_shares = pallet_pooled_staking::pools::ManualRewards::<Runtime>::stake_to_shares(&candidate, pallet_pooled_staking::Stake(amount.into())).map(|x| x.0).unwrap_or(0);
                        if num_shares == 0 {
                            assert_err!(Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Stake(amount.into()),
                            ), pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero);
                            return;
                        }

                        if amount > total_staked {
                            let err = Staking::request_undelegate(
                                RuntimeOrigin::signed(delegator.into()),
                                candidate,
                                pool.into(),
                                SharesOrStake::Stake(amount.into()),
                            ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {

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

            FuzzExtrinsic::ExecutePending {
                operations
            } => {
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
                        }]
                    );
                }
            }

            FuzzExtrinsic::RebalanceHold {
                candidate,
                delegator,
                pool,
            } => {
                let storage_pools: Vec<_> = Pools::<Runtime>::iter().filter(|(candidate1, _key, _amount)| *candidate1 == AccountId::from(candidate.clone())).collect();
                // Handle empty pools
                if storage_pools.is_empty() {
                    assert_err!(Staking::rebalance_hold(
                        RuntimeOrigin::signed(0),
                        candidate.into(),
                        delegator.into(),
                        pool.into(),
                    ), pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking);
                    return;
                }

                // Check that the target pool is not empty
                match &pool {
                    FuzzAllTargetPool::Joining => {
                        let pool_total_stake = storage_pools.iter().filter_map(|(_candidate, key, amount)| match key {
                            PoolsKey::JoiningSharesTotalStaked => Some(*amount),
                            _ => None,
                        }).next().unwrap_or(0);

                        if pool_total_stake == 0 {
                            assert_err!(Staking::rebalance_hold(
                                RuntimeOrigin::signed(0),
                                candidate.into(),
                                delegator.into(),
                                pool.into(),
                            ), pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking);
                            return;
                        }
                    }
                    FuzzAllTargetPool::AutoCompounding => {
                        let pool_total_stake = storage_pools.iter().filter_map(|(_candidate, key, amount)| match key {
                            PoolsKey::AutoCompoundingSharesTotalStaked => Some(*amount),
                            _ => None,
                        }).next().unwrap_or(0);

                        if pool_total_stake == 0 {
                            assert_err!(Staking::rebalance_hold(
                                RuntimeOrigin::signed(0),
                                candidate.into(),
                                delegator.into(),
                                pool.into(),
                            ), pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking);
                            return;
                        }
                    }
                    FuzzAllTargetPool::ManualRewards => {
                        let pool_total_stake = storage_pools.iter().filter_map(|(_candidate, key, amount)| match key {
                            PoolsKey::ManualRewardsSharesTotalStaked => Some(*amount),
                            _ => None,
                        }).next().unwrap_or(0);

                        if pool_total_stake == 0 {
                            assert_err!(Staking::rebalance_hold(
                                RuntimeOrigin::signed(0),
                                candidate.into(),
                                delegator.into(),
                                pool.into(),
                            ), pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking);
                            return;
                        }
                    }
                    FuzzAllTargetPool::Leaving => {
                        let pool_total_stake = storage_pools.iter().filter_map(|(_candidate, key, amount)| match key {
                            PoolsKey::LeavingSharesTotalStaked => Some(*amount),
                            _ => None,
                        }).next().unwrap_or(0);

                        if pool_total_stake == 0 {
                            assert_err!(Staking::rebalance_hold(
                                RuntimeOrigin::signed(0),
                                candidate.into(),
                                delegator.into(),
                                pool.into(),
                            ), pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking);
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

            FuzzExtrinsic::ExecutePendingByIndex {
                i
            } => {
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
                    }]
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
                        let total_staked = Pools::<Runtime>::get(candidate, PoolsKey::AutoCompoundingSharesHeldStake { delegator: delegator.clone().into() });
                        if total_staked == 0 {
                            let amount = 1u8;
                            let err = Staking::request_undelegate(
                                    RuntimeOrigin::signed(delegator.clone().into()),
                                    candidate,
                                    pool.clone().into(),
                                    SharesOrStake::Stake(amount.into()),
                                ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into() {

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
                        let total_staked = Pools::<Runtime>::get(candidate, PoolsKey::ManualRewardsSharesHeldStake { delegator: delegator.clone().into() });
                        if total_staked == 0 {
                            let amount = 1u8;
                            let err = Staking::request_undelegate(
                                    RuntimeOrigin::signed(delegator.clone().into()),
                                    candidate,
                                    pool.clone().into(),
                                    SharesOrStake::Stake(amount.into()),
                                ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into() {

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
                let amount = <Runtime as pallet_pooled_staking::Config>::Currency::free_balance(&delegator.clone().into()).saturating_sub(ExistentialDeposit::get());
                let min_amount = 10 * MEGA;
                if amount < min_amount {
                    return;
                }

                tests::do_request_delegation(candidate.into(), delegator.into(), pool.into(), amount, round_down(amount, 2));
            }

            FuzzExtrinsic::LeaveShares {
                candidate,
                delegator,
                pool,
                shares,
            } => {
                if shares == 0 {
                    assert_err!(Staking::request_undelegate(
                        RuntimeOrigin::signed(delegator.clone().into()),
                        candidate.into(),
                        pool.clone().into(),
                        SharesOrStake::Shares(shares.into()),
                    ), pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero);
                    return;
                }

                // Check that candidate is in pool
                let candidate = candidate.into();

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        let total_staked = Pools::<Runtime>::get(candidate, PoolsKey::AutoCompoundingSharesHeldStake { delegator: delegator.clone().into() });
                        if total_staked == 0 {
                            let err = Staking::request_undelegate(
                                    RuntimeOrigin::signed(delegator.clone().into()),
                                    candidate,
                                    pool.clone().into(),
                                    SharesOrStake::Shares(shares.into()),
                                ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {

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
                            ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {

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
                        let total_staked = Pools::<Runtime>::get(candidate, PoolsKey::ManualRewardsSharesHeldStake { delegator: delegator.clone().into() });
                        if total_staked == 0 {
                            let err = Staking::request_undelegate(
                                    RuntimeOrigin::signed(delegator.clone().into()),
                                    candidate,
                                    pool.clone().into(),
                                    SharesOrStake::Shares(shares.into()),
                                ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::StakeMustBeNonZero.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::NoOneIsStaking.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {

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
                            ).unwrap_err();
                            if err == pallet_pooled_staking::Error::<Runtime>::MathOverflow.into() {

                            } else if err == pallet_pooled_staking::Error::<Runtime>::MathUnderflow.into() {

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

            FuzzExtrinsic::LeavePool {
                delegator,
                pool,
            } => {
                let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        for (candidate, key, amount) in storage_pools {
                            if let PoolsKey::AutoCompoundingSharesHeldStake { delegator: delegator1 } = key {
                                if delegator1 == AccountId::from(delegator.clone()) {
                                    FuzzExtrinsic::LeaveFullAmount {
                                        candidate: FuzzAccountId(candidate as u8),
                                        delegator: delegator.clone(),
                                        pool: pool.clone(),
                                    }.execute(block_number);
                                }
                            }
                        }
                    }
                    FuzzTargetPool::ManualRewards => {
                        for (candidate, key, amount) in storage_pools {
                            if let PoolsKey::ManualRewardsSharesHeldStake { delegator: delegator1 } = key {
                                if delegator1 == AccountId::from(delegator.clone()) {
                                    FuzzExtrinsic::LeaveFullAmount {
                                        candidate: FuzzAccountId(candidate as u8),
                                        delegator: delegator.clone(),
                                        pool: pool.clone(),
                                    }.execute(block_number);
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
                        }]
                    );
                }
            }

            FuzzExtrinsic::EmptyPool {
                pool,
            } => {
                let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();

                match &pool {
                    FuzzTargetPool::AutoCompounding => {
                        for (candidate, key, amount) in storage_pools {
                            if let PoolsKey::AutoCompoundingSharesHeldStake { delegator: delegator1 } = key {
                                FuzzExtrinsic::LeavePool {
                                    delegator: FuzzAccountId(delegator1 as u8),
                                    pool: pool.clone(),
                                }.execute(block_number);
                            }
                        }
                    }
                    FuzzTargetPool::ManualRewards => {
                        for (candidate, key, amount) in storage_pools {
                            if let PoolsKey::ManualRewardsSharesHeldStake { delegator: delegator1 } = key {
                                FuzzExtrinsic::LeavePool {
                                    delegator: FuzzAccountId(delegator1 as u8),
                                    pool: pool.clone(),
                                }.execute(block_number);
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
    ExtBuilder::default().with_balances(balances).build().execute_with(|| {
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
        FuzzExtrinsic::EmptyPool { pool: FuzzTargetPool::AutoCompounding }.execute(block_number);
        FuzzExtrinsic::EmptyPool { pool: FuzzTargetPool::ManualRewards }.execute(block_number);
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

        // Pallet staking doesn't have any storage
        let storage_pools: Vec<_> = Pools::<Runtime>::iter().collect();
        assert_eq!(storage_pools, vec![]);
        //eprintln!("ending test");
    });
}

fuzz_target!(|data: FuzzData| {
    fuzz_main(data)
});

// https://stackoverflow.com/a/51272639
fn is_sorted<T>(data: &[T]) -> bool
where
    T: Ord,
{
    data.windows(2).all(|w| w[0] <= w[1])
}

mod tests {
use pallet_pooled_staking::{PendingOperationKey, SharesOrStake};

use {
    crate::assert_eq_events,
    crate::assert_fields_eq,
    crate::mock::*,
    crate::pool_test,
    pallet_pooled_staking::{
        candidate::Candidates,
        pools::{self, Pool},
        AllTargetPool, Error, Event, PendingOperationQuery, Shares, Stake, TargetPool,
    },
    frame_support::{assert_noop, assert_ok, traits::tokens::fungible::Mutate},
    sp_runtime::TokenError,
};

type Joining = pools::Joining<Runtime>;
type Leaving = pools::Leaving<Runtime>;

pub fn do_request_delegation(
    candidate: AccountId,
    delegator: AccountId,
    pool: TargetPool,
    amount: Balance,
    expected_joining: Balance,
) {
    let before = State::extract(candidate, delegator);
    let pool_before = PoolState::extract::<Joining>(candidate, delegator);

    assert_ok!(Staking::request_delegate(
        RuntimeOrigin::signed(delegator),
        candidate,
        pool,
        amount,
    ));

    let after = State::extract(candidate, delegator);
    let pool_after = PoolState::extract::<Joining>(candidate, delegator);

    // Actual balances don't change
    assert_fields_eq!(before, after, [delegator_balance, staking_balance]);
    assert_eq!(
        before.delegator_hold + expected_joining,
        after.delegator_hold
    );
    assert_eq!(pool_before.hold + expected_joining, pool_after.hold);
    assert_eq!(pool_before.stake + expected_joining, pool_after.stake);
    assert_eq!(
        before.candidate_total_stake + expected_joining,
        after.candidate_total_stake
    );
}

fn do_execute_delegation<P: PoolExt<Runtime>>(
    candidate: AccountId,
    delegator: AccountId,
    block_number: u64,
    expected_increase: Balance,
) {
    let before = State::extract(candidate, delegator);
    let joining_before = PoolState::extract::<Joining>(candidate, delegator);
    let pool_before = PoolState::extract::<P>(candidate, delegator);
    let request_before = crate::PendingOperations::<Runtime>::get(
        delegator,
        P::joining_operation_key(candidate, block_number),
    );
    let request_before =
        pools::Joining::<Runtime>::shares_to_stake(&candidate, Shares(request_before))
            .unwrap()
            .0;

    let refund = request_before
        .checked_sub(expected_increase)
        .expect("expected increase should be <= requested amount");

    assert_ok!(Staking::execute_pending_operations(
        RuntimeOrigin::signed(delegator),
        vec![PendingOperationQuery {
            delegator: delegator,
            operation: P::joining_operation_key(candidate, block_number)
        }]
    ));

    let after = State::extract(candidate, delegator);
    let joining_after = PoolState::extract::<Joining>(candidate, delegator);
    let pool_after = PoolState::extract::<P>(candidate, delegator);
    let request_after = crate::PendingOperations::<Runtime>::get(
        delegator,
        P::joining_operation_key(candidate, block_number),
    );

    // Actual balances don't change
    assert_fields_eq!(before, after, [delegator_balance, staking_balance]);
    // However funds are held (with share rounding released)
    assert_eq!(request_after, 0);

    assert_eq!(before.delegator_hold - refund, after.delegator_hold);
    assert_eq!(
        before.candidate_total_stake - refund,
        after.candidate_total_stake
    );

    assert_eq!(joining_before.hold - request_before, joining_after.hold);
    assert_eq!(joining_before.stake - request_before, joining_after.stake);

    assert_eq!(pool_before.hold + expected_increase, pool_after.hold);
    assert_eq!(pool_before.stake + expected_increase, pool_after.stake);
}

fn do_full_delegation<P: PoolExt<Runtime>>(
    candidate: AccountId,
    delegator: AccountId,
    request_amount: Balance,
    expected_increase: Balance,
) {
    let block_number = block_number();
    do_request_delegation(
        candidate,
        delegator,
        P::target_pool(),
        request_amount,
        round_down(request_amount, 2),
    );
    roll_to(block_number + 2);
    do_execute_delegation::<P>(
        ACCOUNT_CANDIDATE_1,
        ACCOUNT_DELEGATOR_1,
        block_number,
        expected_increase,
    );
}

fn do_request_undelegation<P: PoolExt<Runtime>>(
    candidate: AccountId,
    delegator: AccountId,
    request_amount: Balance,
    expected_removed: Balance,
    expected_leaving: Balance,
) {
    let dust = expected_removed
        .checked_sub(expected_leaving)
        .expect("should removed >= leaving");

    let before = State::extract(candidate, delegator);
    let pool_before = PoolState::extract::<P>(candidate, delegator);
    let leaving_before = PoolState::extract::<Leaving>(candidate, delegator);

    assert_ok!(Staking::request_undelegate(
        RuntimeOrigin::signed(delegator),
        candidate,
        P::target_pool(),
        SharesOrStake::Stake(request_amount),
    ));

    let after = State::extract(candidate, delegator);
    let pool_after = PoolState::extract::<P>(candidate, delegator);
    let leaving_after = PoolState::extract::<Leaving>(candidate, delegator);

    // Actual balances don't change
    assert_fields_eq!(before, after, [delegator_balance, staking_balance]);
    // Dust is released immediately.
    assert_eq!(before.delegator_hold - dust, after.delegator_hold);
    assert_eq!(
        before.candidate_total_stake - dust,
        after.candidate_total_stake
    );
    // Pool decrease.
    assert_eq!(pool_before.stake - expected_removed, pool_after.stake);
    assert_eq!(pool_before.hold - expected_removed, pool_after.stake);
    // Leaving increase.
    assert_eq!(leaving_before.stake + expected_leaving, leaving_after.stake);
    assert_eq!(leaving_before.hold + expected_leaving, leaving_after.stake);
}

fn do_execute_undelegation(
    candidate: AccountId,
    delegator: AccountId,
    block_number: u64,
    expected_decrease: Balance,
) {
    let before = State::extract(candidate, delegator);
    let leaving_before = PoolState::extract::<Leaving>(candidate, delegator);

    assert_ok!(Staking::execute_pending_operations(
        RuntimeOrigin::signed(delegator),
        vec![PendingOperationQuery {
            delegator: delegator,
            operation: PendingOperationKey::Leaving {
                candidate,
                at_block: block_number
            }
        }]
    ));

    let after = State::extract(candidate, delegator);
    let leaving_after = PoolState::extract::<Joining>(candidate, delegator);
    let request_after = crate::PendingOperations::<Runtime>::get(
        delegator,
        PendingOperationKey::Leaving {
            candidate,
            at_block: block_number,
        },
    );

    // Actual balances don't change
    assert_fields_eq!(before, after, [delegator_balance, staking_balance]);
    assert_eq!(request_after, 0);
    assert_eq!(
        before.delegator_hold - expected_decrease,
        after.delegator_hold
    );
    assert_eq!(
        before.candidate_total_stake - expected_decrease,
        after.candidate_total_stake
    );
    assert_eq!(leaving_before.hold - expected_decrease, leaving_after.hold);
    assert_eq!(
        leaving_before.stake - expected_decrease,
        leaving_after.stake
    );
}

fn do_full_undelegation<P: PoolExt<Runtime>>(
    candidate: AccountId,
    delegator: AccountId,
    request_amount: Balance,
    expected_removed: Balance,
    expected_leaving: Balance,
) {
    let block_number = block_number();
    do_request_undelegation::<P>(
        candidate,
        delegator,
        request_amount,
        expected_removed,
        expected_leaving,
    );
    roll_to(block_number + 2);
    do_execute_undelegation(candidate, delegator, block_number, expected_leaving);
}

fn do_rebalance_hold<P: Pool<Runtime>>(
    candidate: AccountId,
    delegator: AccountId,
    target_pool: AllTargetPool,
    expected_rebalance: SignedBalance,
) {
    let before = State::extract(candidate, delegator);
    let pool_before = PoolState::extract::<P>(candidate, delegator);

    assert_ok!(Staking::rebalance_hold(
        RuntimeOrigin::signed(ACCOUNT_DELEGATOR_1),
        ACCOUNT_CANDIDATE_1,
        ACCOUNT_DELEGATOR_1,
        target_pool
    ));

    let after = State::extract(candidate, delegator);
    let pool_after = PoolState::extract::<P>(candidate, delegator);

    // Balances should update
    match expected_rebalance {
        SignedBalance::Positive(balance) => {
            assert_eq!(pool_before.hold + balance, pool_after.hold);
            assert_eq!(before.delegator_balance + balance, after.delegator_balance);
            assert_eq!(before.staking_balance - balance, after.staking_balance);
        }
        SignedBalance::Negative(balance) => {
            assert_eq!(pool_before.hold - balance, pool_after.hold);
            assert_eq!(before.delegator_balance - balance, after.delegator_balance);
            assert_eq!(before.staking_balance + balance, after.staking_balance);
        }
    }

    // Stake stay the same.
    assert_fields_eq!(pool_before, pool_after, stake);
}
}

mod mock {
// Copyright (C) Moondance Labs Ltd.
// This file is part of Tanssi.

// Tanssi is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Tanssi is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Tanssi.  If not, see <http://www.gnu.org/licenses/>

use {
    pallet_pooled_staking::{
        candidate::Candidates, pools::Pool, Candidate, Delegator,
        PendingOperationKey, RequestFilter, TargetPool,
    },
    frame_support::{
        parameter_types,
        traits::{
            tokens::fungible::{Inspect, InspectHold},
            Everything, OnFinalize, OnInitialize,
        },
    },
    frame_system::pallet_prelude::BlockNumberFor,
    num_traits::Num,
    parity_scale_codec::{Decode, Encode, MaxEncodedLen},
    scale_info::TypeInfo,
    sp_core::{ConstU32, ConstU64, RuntimeDebug, H256},
    sp_runtime::{
        testing::Header,
        traits::{BlakeTwo256, BlockNumberProvider, IdentityLookup},
        Perbill,
    },
};

#[derive(
    RuntimeDebug,
    PartialEq,
    Eq,
    Encode,
    Decode,
    Copy,
    Clone,
    TypeInfo,
    PartialOrd,
    Ord,
    MaxEncodedLen,
)]
pub enum HoldIdentifier {
    Staking,
}

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Runtime>;
type Block = frame_system::mocking::MockBlock<Runtime>;
pub type AccountId = u64;
pub type Balance = u128;

pub const ACCOUNT_STAKING: u64 = 0;
pub const ACCOUNT_CANDIDATE_1: u64 = 1;
pub const ACCOUNT_CANDIDATE_2: u64 = 2;
pub const ACCOUNT_DELEGATOR_1: u64 = 3;
pub const ACCOUNT_DELEGATOR_2: u64 = 4;

pub const KILO: u128 = 1000;
pub const MEGA: u128 = 1000 * KILO;
pub const GIGA: u128 = 1000 * MEGA;
pub const TERA: u128 = 1000 * GIGA;
pub const PETA: u128 = 1000 * TERA;
pub const DEFAULT_BALANCE: u128 = PETA;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = Block,
        UncheckedExtrinsic = UncheckedExtrinsic,
    {
        System: frame_system,
        Balances: pallet_balances,
        Staking: pallet_pooled_staking,
    }
);

impl frame_system::Config for Runtime {
    type BaseCallFilter = Everything;
    type BlockWeights = ();
    type BlockLength = ();
    type DbWeight = ();
    type RuntimeOrigin = RuntimeOrigin;
    type RuntimeCall = RuntimeCall;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type RuntimeEvent = RuntimeEvent;
    type BlockHashCount = ConstU64<250>;
    type Version = ();
    type PalletInfo = PalletInfo;
    type AccountData = pallet_balances::AccountData<Balance>;
    type OnNewAccount = ();
    type OnKilledAccount = ();
    type SystemWeightInfo = ();
    type SS58Prefix = ();
    type OnSetCode = ();
    type MaxConsumers = ConstU32<16>;
}

parameter_types! {
    pub const ExistentialDeposit: u128 = 1;
}

impl pallet_balances::Config for Runtime {
    type MaxReserves = ();
    type ReserveIdentifier = [u8; 4];
    type MaxLocks = ();
    type Balance = Balance;
    type RuntimeEvent = RuntimeEvent;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
    type FreezeIdentifier = ();
    type MaxFreezes = ();
    type HoldIdentifier = HoldIdentifier;
    type MaxHolds = ConstU32<5>;
    type WeightInfo = ();
}

parameter_types! {
    pub const StakingAccount: u64 = ACCOUNT_STAKING;
    pub const CurrencyHoldReason: HoldIdentifier = HoldIdentifier::Staking;
    pub const InitialManualClaimShareValue: u128 = MEGA;
    pub const InitialAutoCompoundingShareValue: u128 = MEGA;
    pub const InitialJoiningShareValue: u128 = 2; // to test rounding
    pub const InitialLeavingShareValue: u128 = 3; // to test rounding
    pub const MinimumSelfDelegation: u128 = 10 * MEGA;
    pub const RewardsCollatorCommission: Perbill = Perbill::from_percent(20);
}

pub struct DummyRequestFilter;

impl RequestFilter<Runtime> for DummyRequestFilter {
    fn can_be_executed(_: &Candidate<Runtime>, _: &Delegator<Runtime>, request_block: u64) -> bool {
        let block_number = frame_system::Pallet::<Runtime>::current_block_number();

        let Some(diff) = block_number.checked_sub(request_block) else {
            return false;
        };

        diff >= 2 // must wait 2 blocks
    }
}

impl pallet_pooled_staking::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type Currency = Balances;
    type Balance = Balance;
    type CurrencyHoldReason = CurrencyHoldReason;
    type StakingAccount = StakingAccount;
    type InitialManualClaimShareValue = InitialManualClaimShareValue;
    type InitialAutoCompoundingShareValue = InitialAutoCompoundingShareValue;
    type InitialJoiningShareValue = InitialJoiningShareValue;
    type InitialLeavingShareValue = InitialLeavingShareValue;
    type MinimumSelfDelegation = MinimumSelfDelegation;
    type RewardsCollatorCommission = RewardsCollatorCommission;
    type JoiningRequestFilter = DummyRequestFilter;
    type LeavingRequestFilter = DummyRequestFilter;
    // low value so we can test vec bounding, in practice it should be bigger
    type EligibleCandidatesBufferSize = ConstU32<4>;
}

pub trait PoolExt<T: pallet_pooled_staking::Config>: Pool<T> {
    fn target_pool() -> TargetPool;
    fn event_staked(
        candidate: Candidate<T>,
        delegator: Delegator<T>,
        shares: T::Balance,
        stake: T::Balance,
    ) -> pallet_pooled_staking::Event<T>;
    fn joining_operation_key(
        candidate: Candidate<T>,
        at_block: T::BlockNumber,
    ) -> PendingOperationKey<Candidate<T>, T::BlockNumber>;
}

impl<T: pallet_pooled_staking::Config> PoolExt<T> for pallet_pooled_staking::pools::ManualRewards<T> {
    fn target_pool() -> TargetPool {
        TargetPool::ManualRewards
    }

    fn event_staked(
        candidate: Candidate<T>,
        delegator: Delegator<T>,
        shares: T::Balance,
        stake: T::Balance,
    ) -> pallet_pooled_staking::Event<T> {
        pallet_pooled_staking::Event::StakedManualRewards {
            candidate,
            delegator,
            shares,
            stake,
        }
    }

    fn joining_operation_key(
        candidate: Candidate<T>,
        at_block: T::BlockNumber,
    ) -> PendingOperationKey<Candidate<T>, T::BlockNumber> {
        PendingOperationKey::JoiningManualRewards {
            candidate,
            at_block,
        }
    }
}

impl<T: pallet_pooled_staking::Config> PoolExt<T> for pallet_pooled_staking::pools::AutoCompounding<T> {
    fn target_pool() -> TargetPool {
        TargetPool::AutoCompounding
    }
    fn event_staked(
        candidate: Candidate<T>,
        delegator: Delegator<T>,
        shares: T::Balance,
        stake: T::Balance,
    ) -> pallet_pooled_staking::Event<T> {
        pallet_pooled_staking::Event::StakedAutoCompounding {
            candidate,
            delegator,
            shares,
            stake,
        }
    }

    fn joining_operation_key(
        candidate: Candidate<T>,
        at_block: T::BlockNumber,
    ) -> PendingOperationKey<Candidate<T>, T::BlockNumber> {
        PendingOperationKey::JoiningAutoCompounding {
            candidate,
            at_block,
        }
    }
}

#[macro_export]
macro_rules! pool_test {
    (fn $name:ident<$pool:ident>() { $body:expr }) => {
        mod $name {
            use super::*;
            fn generic<$pool: PoolExt<Runtime>>() {
                $body
            }

            #[test]
            fn manual() {
                generic::<pools::ManualRewards<Runtime>>();
            }

            #[test]
            fn auto() {
                generic::<pools::AutoCompounding<Runtime>>();
            }
        }
    };
}

pub fn total_balance(who: &AccountId) -> Balance {
    Balances::total_balance(who)
}

pub fn balance_hold(who: &AccountId) -> Balance {
    Balances::balance_on_hold(&HoldIdentifier::Staking, who)
}

pub fn block_number() -> BlockNumberFor<Runtime> {
    System::block_number()
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct State {
    pub delegator_balance: Balance,
    pub delegator_hold: Balance,
    pub staking_balance: Balance,
    pub candidate_total_stake: Balance,
}

impl State {
    pub fn extract(candidate: AccountId, delegator: AccountId) -> Self {
        Self {
            delegator_balance: total_balance(&delegator),
            delegator_hold: balance_hold(&delegator),
            staking_balance: total_balance(&ACCOUNT_STAKING),
            candidate_total_stake: Candidates::<Runtime>::total_stake(&candidate).0,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PoolState {
    pub hold: Balance,
    pub stake: Balance,
}

impl PoolState {
    pub fn extract<P: Pool<Runtime>>(candidate: AccountId, delegator: AccountId) -> Self {
        Self {
            hold: P::hold(&candidate, &delegator).0,
            stake: P::computed_stake(&candidate, &delegator)
                .expect("invalid state")
                .0,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SignedBalance {
    Positive(Balance),
    Negative(Balance),
}

#[allow(dead_code)]
pub fn round_down<T: Num + Copy>(value: T, increment: T) -> T {
    if (value % increment).is_zero() {
        value
    } else {
        (value / increment) * increment
    }
}

pub(crate) struct ExtBuilder {
    // endowed accounts with balances
    balances: Vec<(AccountId, Balance)>,
}

impl Default for ExtBuilder {
    fn default() -> ExtBuilder {
        ExtBuilder {
            balances: vec![
                (ACCOUNT_STAKING, 1 * DEFAULT_BALANCE),
                (ACCOUNT_CANDIDATE_1, 1 * DEFAULT_BALANCE),
                (ACCOUNT_CANDIDATE_2, 1 * DEFAULT_BALANCE),
                (ACCOUNT_DELEGATOR_1, 1 * DEFAULT_BALANCE),
                (ACCOUNT_DELEGATOR_2, 1 * DEFAULT_BALANCE),
            ],
        }
    }
}

impl ExtBuilder {
    #[allow(dead_code)]
    pub(crate) fn with_balances(mut self, balances: Vec<(AccountId, Balance)>) -> Self {
        self.balances = balances;
        self
    }

    pub(crate) fn build(self) -> sp_io::TestExternalities {
        let mut t = frame_system::GenesisConfig::default()
            .build_storage::<Runtime>()
            .expect("Frame system builds valid default genesis config");

        pallet_balances::GenesisConfig::<Runtime> {
            balances: self.balances,
        }
        .assimilate_storage(&mut t)
        .expect("Pallet balances storage can be assimilated");

        let mut ext = sp_io::TestExternalities::new(t);
        ext.execute_with(|| System::set_block_number(1));
        ext
    }
}

/// Rolls forward one block. Returns the new block number.
#[allow(dead_code)]
pub(crate) fn roll_one_block() -> u64 {
    // Staking::on_finalize(System::block_number());
    Balances::on_finalize(System::block_number());
    System::on_finalize(System::block_number());
    System::set_block_number(System::block_number() + 1);
    System::on_initialize(System::block_number());
    Balances::on_initialize(System::block_number());
    // Staking::on_initialize(System::block_number());
    System::block_number()
}

/// Rolls to the desired block. Returns the number of blocks played.
#[allow(dead_code)]
pub(crate) fn roll_to(n: u64) -> u64 {
    let mut num_blocks = 0;
    let mut block = System::block_number();
    while block < n {
        block = roll_one_block();
        num_blocks += 1;
    }
    num_blocks
}

#[allow(dead_code)]
pub(crate) fn last_event() -> RuntimeEvent {
    System::events().pop().expect("Event expected").event
}

#[allow(dead_code)]
pub(crate) fn events() -> Vec<pallet_pooled_staking::Event<Runtime>> {
    System::events()
        .into_iter()
        .map(|r| r.event)
        .filter_map(|e| {
            if let RuntimeEvent::Staking(inner) = e {
                Some(inner)
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
}

/// Assert input equal to the last event emitted
#[macro_export]
macro_rules! assert_last_event {
    ($event:expr) => {
        match &$event {
            e => assert_eq!(*e, pallet_pooled_staking::mock::last_event()),
        }
    };
}

/// Compares the system events with passed in events
/// Prints highlighted diff iff assert_eq fails
#[macro_export]
macro_rules! assert_eq_events {
    ($events:expr) => {
        match &$events {
            e => similar_asserts::assert_eq!(*e, pallet_pooled_staking::mock::events()),
        }
    };
}

/// Compares the last N system events with passed in events, where N is the length of events passed
/// in.
///
/// Prints highlighted diff iff assert_eq fails.
/// The last events from frame_system will be taken in order to match the number passed to this
/// macro. If there are insufficient events from frame_system, they will still be compared; the
/// output may or may not be helpful.
///
/// Examples:
/// If frame_system has events [A, B, C, D, E] and events [C, D, E] are passed in, the result would
/// be a successful match ([C, D, E] == [C, D, E]).
///
/// If frame_system has events [A, B, C, D] and events [B, C] are passed in, the result would be an
/// error and a hopefully-useful diff will be printed between [C, D] and [B, C].
///
/// Note that events are filtered to only match parachain-staking (see events()).
#[macro_export]
macro_rules! assert_eq_last_events {
    ($events:expr) => {
        assert_tail_eq!($events, pallet_pooled_staking::mock::events());
    };
}

/// Assert that one array is equal to the tail of the other. A more generic and testable version of
/// assert_eq_last_events.
#[macro_export]
macro_rules! assert_tail_eq {
    ($tail:expr, $arr:expr) => {
        if $tail.len() != 0 {
            // 0-length always passes

            if $tail.len() > $arr.len() {
                similar_asserts::assert_eq!($tail, $arr); // will fail
            }

            let len_diff = $arr.len() - $tail.len();
            similar_asserts::assert_eq!($tail, $arr[len_diff..]);
        }
    };
}

/// Panics if an event is not found in the system log of events
#[macro_export]
macro_rules! assert_event_emitted {
    ($event:expr) => {
        match &$event {
            e => {
                assert!(
                    pallet_pooled_staking::mock::events().iter().find(|x| *x == e).is_some(),
                    "Event {:?} was not found in events: \n {:?}",
                    e,
                    pallet_pooled_staking::mock::events()
                );
            }
        }
    };
}

/// Panics if an event is found in the system log of events
#[macro_export]
macro_rules! assert_event_not_emitted {
    ($event:expr) => {
        match &$event {
            e => {
                assert!(
                    pallet_pooled_staking::mock::events().iter().find(|x| *x == e).is_none(),
                    "Event {:?} was found in events: \n {:?}",
                    e,
                    pallet_pooled_staking::mock::events()
                );
            }
        }
    };
}

#[macro_export]
macro_rules! assert_fields_eq {
    ($left:expr, $right:expr, $field:ident) => {
        assert_eq!($left.$field, $right.$field);
    };
    ($left:expr, $right:expr, [$( $field:ident ),+ $(,)?] ) => {
        $(
            assert_eq!($left.$field, $right.$field);
        )+
    };
}

#[test]
fn assert_tail_eq_works() {
    assert_tail_eq!(vec![1, 2], vec![0, 1, 2]);

    assert_tail_eq!(vec![1], vec![1]);

    assert_tail_eq!(
        vec![0u32; 0], // 0 length array
        vec![0u32; 1]  // 1-length array
    );

    assert_tail_eq!(vec![0u32, 0], vec![0u32, 0]);
}

#[test]
#[should_panic]
fn assert_tail_eq_panics_on_non_equal_tail() {
    assert_tail_eq!(vec![2, 2], vec![0, 1, 2]);
}

#[test]
#[should_panic]
fn assert_tail_eq_panics_on_empty_arr() {
    assert_tail_eq!(vec![2, 2], vec![0u32; 0]);
}

#[test]
#[should_panic]
fn assert_tail_eq_panics_on_longer_tail() {
    assert_tail_eq!(vec![1, 2, 3], vec![1, 2]);
}

#[test]
#[should_panic]
fn assert_tail_eq_panics_on_unequal_elements_same_length_array() {
    assert_tail_eq!(vec![1, 2, 3], vec![0, 1, 2]);
}
}
