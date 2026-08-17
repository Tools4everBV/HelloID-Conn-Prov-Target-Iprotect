# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.2.0] - 01-07-2025

### Added
- Added support for retrieving departments, authorization groups and FreeSelect fields
- Added support for import permissions script
- Added automatic escaping of special characters (apostrophes and ampersands) in SQL queries to prevent errors
- Added configuration options to control behavior when lookups fail (Error or Clear)
- Added dynamic field detection for FREETEXT and FREESELECT fields

### Fixed
- Fixed SQL injection issues with special characters in department names and other lookup fields
- Several other small fixes

## [1.1.0] - 20-03-2025

Fixes after first implementation. Added import scripts for account and account access.

## [1.0.0] - 19-02-2025

This is the first official release of _HelloID-Conn-Prov-Target-IProtect_. This release is based on template version _2.0.1_.

### Added

### Changed

### Deprecated

### Removed