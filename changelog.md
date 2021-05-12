# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]
### To Do

#### Torpedo
- Add tests for Torpedo AND for torserde_macros
- Make sure that cell serialisation is fast. 
  - Add benchmarks to macro_tests.rs tests
- Make sure inner cells are padded correctly so they fit in normal cells

#### torserde_macros
- Clean up macro code, create functions for repeated code

#### Torserde

### Unfinished Ideas

## [0.1.0] - 2021-05-05
### Added
- Initial commit
- Created `Torserde` trait exposing functions that serialise/deserialise according to Tor specification
- Implemented `Torserde` for various types
- Created tests for `Torserde`  
- Created `Torserde` derive macro to derive for structs and enums