# Changelog

All notable changes to **SupplyGuard** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.2] - 2026-04-14

### Fixed
- Status bar vulnerability count not updating after fixing a vulnerable dependency. Previously, the 1-hour cache was reused on file save, causing stale counts to persist. Now a fresh scan is forced on every save (`force=true`), so the count reflects the actual current state immediately.

---

## [1.0.1] - 2026-04-04

### Added
- Manual vulnerability database support via `supplyguard.json` in the workspace root. Teams can flag internal blacklisted packages/versions with custom severity and details.
- Multi-ecosystem support: npm, PyPI, Maven, Go (go.mod), and Cargo (Cargo.toml).
- Batch vulnerability querying via OSV API (`/v1/querybatch`) for faster scans.
- Supply-chain risk detection: flags npm packages published within the last 48 hours.
- Tree view panel (`supplyguard-view`) listing vulnerable files, dependencies, and individual CVEs.
- Status bar indicator showing total vulnerability count or "Clear" when safe.
- Click-through from tree view items to the OSV vulnerability detail page.
- 1-hour in-memory cache to avoid redundant API calls on file open.
- `supplyguard.scan` command to trigger a manual workspace-wide rescan.

### Changed
- Diagnostics now use `Error` severity for supply-chain risks and `Warning` for known CVEs.

---

## [1.0.0] - 2026-04-02

### Added
- Initial release of SupplyGuard.
- npm `package.json` scanning against the OSV vulnerability database.
- Inline diagnostics highlighting vulnerable dependency lines in the editor.
