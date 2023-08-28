# Setup

Install requirements

```
cargo install cargo-fuzz
```

Make sure you clone this repo right next to the tanssi folder (`cd ../tanssi` should work)

```
git clone https://github.com/tmpolaczyk/fuzz-pallet-staking
cd fuzz-pallet-staking
```

Apply manual patch to tanssi repo

```
cd ../tanssi
git fetch origin
git checkout origin/jeremy-pooled-staking
# Modify pallets/pooled-staking/src/lib.rs , make all modules public
cd ../fuzz-pallet-staking
```

If the pallet has been updated since I last pushed to this repo, you may need to copy mock.rs and tests again:

```
cp ../tanssi/pallets/pooled-staking/src/mock.rs fuzz/fuzz_targets/mock.rs
cp -rf ../tanssi/pallets/pooled-staking/src/tests/* fuzz/fuzz_targets/tests/
```

And fix any imports errors by changing `crate::` to `pallet_pooled_staking::`, except
`pallet_pooled_staking::mock` which should be `crate::mock`.

# Run

```
cargo fuzz run fuzz_target_1
# Or using 8 threads
cargo fuzz run fuzz_target_1 -j8
```

Remove the `println!` calls if the output is too verbose.

# Coverage

```
cd fuzz
cargo fuzz coverage fuzz_target_1
$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov show target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_target_1     --format=html     -instr-profile=coverage/fuzz_target_1/coverage.profdata  --ignore-filename-regex='.*/\.cargo/.*'   > index.html
firefox index.html
```
