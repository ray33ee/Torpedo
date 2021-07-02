# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### To Do

#### Torpedo

- Only fetch a new consensus/router data if expired. Otherwise try to use cached data
- Don't keep allocating memory (via Vec) try to use one global Vec and reuse it for multiple cells

#### torserde_macros
- Clean up macro code, create functions for repeated code

#### Torserde
- Rename `NLengthVector` to something less confusing

### Unfinished Ideas
None

## [0.1.5] - 2021-07-01
### Added
- `torserde::ErrorKind::InvalidRelayLength` error added to show when a serialised cell is not the correct length of 509 bytes
- misc.rs for particular snippets belonging to no specific branch of Torpedo
- `misc::UnpackedCell` added to help with the fast serialization and deserialization of `Relay`

### Removed
- 'Clone' trait from various types

### Fixed
- `NullReader` renamed to `NullStream` and the `write` function now returns the number of bytes read

## [0.1.4] - 2021-06-16
### Added
- We now flush padding for variable length cells too
- `torserde::ErrorKind` added to encapsulate Torserde-specific errors (like bad digest, invalid command, etc.) and generic errors from `std::io` and `bincode`  
- Torserde trait now returns `torserde::Result` for serialize and deserialize which uses the `torserde::ErrorKind` enum
- The return value from serialisation (i.e. the running total number of bytes serialised) now includes the discriminant for enums
- Support for `torserde::Result` in macros and in `CellCrypto`

## [0.1.3] - 2021-05-26
### Added
- Python script created that converts mirror and directory list into Rust code
- Relay cells implemented
  - Relay cells contain an `Encrypted` struct which mark the payload as ready for decryption and verification
  - The payload of a decrypted cell is essentially an Option, as cells that should have a payload but have a length of zero are represented as None
  - Cellcrypto modified to work with Cells and Encrypted structs instead of buffers
  - Relay cells are padded with random bytes
  - By default, the command and payload are not contiguous for relay cells. We join them together to ensure they can be serialised/deserialised with Torserde
  - Padding is stored in `RelayCell` so it can be used to calculate the rolling digest
- SendMePayload added
- We use the `ring` CSPRNG to generate random padding 
- Various warnings cleared

### Removed
- RelayCommand enum removed as no longer needed

## [0.1.2] - 2021-05-26
### Added
- CryptoCell struct which handles calculation of forward and backward encryption/decryption and digests for relay nodes
- Demonstration of communication down to relay begin and relay connected level.

## [0.1.1] - 2021-05-12
### Added
- The framework for test on Torserde macros and the Torpedo lib
- Removed `payload_length` argument from `bin_deserialise_from` since payloads now include the length at the beginning
- `VersionsVector` updated to use the length (in bytes) supplied by the cell

### Changed
- `serialised_length` calculation for `[0u8; N]` types has been optimised

## [0.1.0] - 2021-05-05
### Added
- Initial commit
- Created `Torserde` trait exposing functions that serialise/deserialise according to Tor specification
- Implemented `Torserde` for various types
- Created tests for `Torserde`  
- Created `Torserde` derive macro to derive for structs and enums