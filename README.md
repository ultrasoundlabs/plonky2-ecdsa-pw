## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

### Test

- nightly

    ```sh
    rustup override set nightly
    ```

- run test
    - succeed

        ```sh
        cargo test --release --package plonky2_ecdsa --lib -- gadgets::ecdsa::tests::test_prove_ecdsa --exact --nocapture --ignored
        ```

    - failure

        ```sh
        cargo test --release --package plonky2_ecdsa --lib -- gadgets::ecdsa::tests::test_failure_fake_pk --exact --nocapture --ignored
        ```

    - recursive

        ```sh
        cargo test --release --package plonky2_ecdsa --lib -- gadgets::ecdsa::tests::test_three_ecdsa_recursive --exact --nocapture --ignored
        ```

- run exec
    - main succeed

        ```sh
        ./run.sh
        ```

## Fixed

- package `nonnative`, `impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderNonNative<F, D>
    for CircuitBuilder<F, D>`, `mul_nonnative`
    - fix according to [PR-1](https://github.com/mir-protocol/plonky2-ecdsa/pull/1)
    - [fix commit](https://github.com/mir-protocol/plonky2-ecdsa/commit/dd03c7d5c156f026d6ba39b63d517b2d447fc6c9)
    - test script:
        ```sh
        cargo test --release --package plonky2_ecdsa --lib -- gadgets::nonnative::tests::test_overflow --exact --nocapture
        ```
