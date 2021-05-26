# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### To Do

#### Torpedo

- Make sure that cell serialisation is fast. 
  - Add benchmarks to macro_tests.rs tests
- Make sure inner cells are padded correctly so they fit in normal cells
- Make sure we ignore padding in variable length cells too
- Convert the directory authority list and fallback mirror list into rust code at compile time
- Make sure we ignore AND flush padding wer don't use
- Also make sure we add padding where needed
- Only fetch a new consensus/router data if expired. Otherwise try to use cached data
- Don't keep allocating memory (via Vec) try to use one global Vec and reuse it for multiple cells

#### torserde_macros
- Clean up macro code, create functions for repeated code
- Modify macro to use the `repr` attribute and serialise the discriminant accordingly (as u8, u16, etc.)
- Figure out why `Command` needs Debug, Clone, == and != traits
- Modify the struct macro to allow customisation
  - The user creates a struct, then derives Torserde
    - Deriving torserde requires the user to specify the order that the fields will be serialised
    - For vectors the user must specify the size of the length data (u8, u16 or u32)
    - For enums the determinant and data are sent separately (determinent must be sent first)
    - The size of the determinant is also customisable

#### Torserde
- Rename `NLengthVector` to something less confusing

### Unfinished Ideas
None

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