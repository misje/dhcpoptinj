# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 0.5.0 - 2019-04-19
### Added
- Parse configuration from file.
- Add copyright to usage output.

### Fixed
- Fix pedantic errors from clang.

## 0.4.4 - 2019-03-25
### Fixed
- Update version number in binary.

## 0.4.3 - 2019-03-19
### Added
- DHCP option names are printed along with their option codes.

### Changed
- Debug output is more detailed and aligned.

### Fixed
- Alignment and explicit data type conversions are used to compile without
  errors on 32-bit architectures.
- Do not fail on strict-overflow warnings, as some may be ignored.
- Do not use non-ASCII characters in debug output. They were not strictly
  needed.

## 0.4.2 - 2019-01-17
### Changed
- Change usage string to reflect formatting used by man page.
- Add very strict compiler flags.

### Fixed
- Fix new compiler warnings (pedantic signed/unsigned issues and void function
  declarations).

## 0.4.1 - 2016-12-18
### Fixed
- Update version number in --version output from 0.3.0.

## 0.4.0 - 2016-12-13
### Changed
- Use constant for maximum queue length instead of hard-coded value.

### Fixed
- Fix program name simplification bug.
- Remove typo in help text.

## 0.3.0 - 2016-06-10
### Added
- Add support for replacing existing DHCP options.
- Allow injecting multiple options of same type.

### Changed
- Update README.
- Improve debug output.
- Improve help text.

### Fixed
- Fix incorrect --version output.
- Drop/accept if packet fragmented depending on --forward-on-fail.
- Safe-guard against empty DHCP options as result of invalid hex strings.
- Fix erroneous new packet size calculation.
- Fix other minor bugs and warnings.

## 0.2.1 - 2015-07-28
### Changed
- Improve documentation

### Fixed
- Fix memory leak on exit with --version/--help.

## 0.2.0 - 2015-07-27
Initial release
