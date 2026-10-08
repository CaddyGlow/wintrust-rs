Vendored from `stringprep` 0.1.5 (https://crates.io/crates/stringprep/0.1.5).
The upstream profiles, Unicode tables, and tests are retained. Portability changes
replace `std` imports with `alloc`/`core`, implement `core::error::Error`, and
allow unused profiles in this private module. Table modules skip rustfmt to keep
the upstream generated data readable and comparable. Unicode dependencies keep
their original compatible version ranges and disable their `std` defaults.

# stringprep

[Documentation](https://docs.rs/stringprep)

An implementation of the stringprep algorithm as defined in [RFC 3454][].

[RFC 3454]: https://tools.ietf.org/html/rfc3454

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
