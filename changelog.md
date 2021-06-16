# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### To Do

#### Torpedo

- Make sure that cell serialisation is fast. 
  - Add benchmarks to macro_tests.rs tests
- Make sure we ignore padding in variable length cells too
- Only fetch a new consensus/router data if expired. Otherwise try to use cached data
- Don't keep allocating memory (via Vec) try to use one global Vec and reuse it for multiple cells
- Make sure we correctly handle invalid discriminants (instead of panicking)
  - Cells with an invalid command are ignored
  - An Invalid SendMePayload enum should result in a tear down of the circuit
  - Return Result when deserialising
- Add a build configuration in Torpedo (as part of test) to call mirror_mirror to generate source

#### torserde_macros
- Clean up macro code, create functions for repeated code
- Modify macro to use the `repr` attribute and serialise the discriminant accordingly (as u8, u16, etc.)
- Figure out why `Command` needs Debug, Clone, == and != traits
- Modify the struct macro to allow customisation
  - The user creates a struct, then derives Torserde with custom arguments describing how to serialise
    - Deriving torserde requires the user to specify the order that the fields will be serialised
    - For vectors the user must specify the size of the length data (u8, u16 or u32)
    - For enums the determinant and data are sent separately (determinant must be sent first)
    - The size of the determinant is also customisable
    - Specifying the order of serialisation should be optional (if it's not specified, use the order that the fields appear in the struct definition)

#### Torserde
- Rename `NLengthVector` to something less confusing

### Unfinished Ideas
None

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