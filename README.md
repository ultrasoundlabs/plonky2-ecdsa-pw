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

    ```sh
    cargo test --release --package plonky2_ecdsa --lib -- gadgets::ecdsa::tests::test_ecdsa_circuit_wide --exact --nocapture --ignored
    ```

    ```sh
    cargo test --release --package plonky2_ecdsa --lib -- gadgets::ecdsa::tests::test_prove_ecdsa --exact --nocapture --ignored
    ```
