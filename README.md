# SupplyGuard: Universal Dependency Vulnerability Checker

SupplyGuard is a powerful VS Code extension designed to protect your projects from supply-chain attacks and known vulnerabilities. It provides a unique "Zero-day Radar" and integrates with OSV.dev to provide comprehensive security across multiple ecosystems.

## Features

### 🚨 Zero-Day Supply-Chain Radar
Identifies packages published within the last 48 hours. This is a critical indicator of potential supply-chain attacks (like the recent axios malicious release).

### 🔍 Universal OSV.Dev Integration
Uses the OSV batch API to check all your dependencies in one request. Supports:
- **Node.js**: `package.json`, `package-lock.json`
- **Python**: `requirements.txt`, `pyproject.toml`, `Pipfile`
- **Java**: `pom.xml`, `build.gradle` (Maven/Gradle)
- **Go**: `go.mod`
- **Rust**: `Cargo.toml`
- **PHP/Ruby/.NET**: Support coming soon!

### 🛠️ Key UX Highlights
- **Inline Diagnostics**: Highlighting vulnerable lines directly in your manifest files.
- **SupplyGuard Sidebar**: A dedicated view in the Activity Bar with a summary of all risks.
- **Problems Panel**: Integrated with VS Code's problems panel for easy navigation.
- **Status Bar Summary**: A quick look at your project's security health.

## How to Use
1. Just open a project with supported manifest files! SupplyGuard scans automatically.
2. Look for red/yellow underlines in your `package.json` or `requirements.txt`.
3. Use the **Shield icon** in the Activity Bar to see a detailed tree view.
4. Click on a vulnerability to view more details on OSV.dev.

## Technical Details
- **Privacy First**: No telemetry, no external services (except OSV.dev and official registries).
- **Lightweight**: Zero extra dependencies, using built-in `https` module.
- **Fast**: Batch queries and local caching for optimal performance.

## License
MIT
