# SupplyGuard - Universal Dependency Vulnerability Checker 🛡️

SupplyGuard is a high-performance VS Code extension designed to safeguard your projects against supply-chain attacks and known vulnerabilities. Built with a "Privacy-First" approach, it provides a unique "Zero-day Radar" to identify suspicious activities before they appear in common databases.

## 🚀 Key Features

### 🚨 Zero-Day Supply-Chain Radar
Identifies packages published within the last **48 hours**. This is a critical indicator of potential supply-chain attacks (like the recent axios malicious release). 

### 🔍 Multi-Ecosystem OSV.dev Integration
Comprehensive security scanning using the OSV batch API for maximum performance.
- **Node.js**: `npm`, `pnpm`, `yarn`, `bun` (`package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`)
- **Python**: `requirements.txt`, `pyproject.toml`, `Pipfile`
- **Go**: `go.mod`
- **Rust**: `Cargo.toml`
- **Java**: `pom.xml` (Maven/Gradle support coming soon!)

### 🛠️ Polished UX & Integration
- **Inline Diagnostics**: Visual highlights and error messages directly in your manifest files.
- **Shield Sidebar**: A dedicated Activity Bar view containing the full vulnerability tree.
- **Problems Panel**: Native integration for easy navigation between risks.
- **Status Bar Indicator**: Real-time project security status at a glance.

## 🛠️ Installation & Usage
1.  **Open any project**: SupplyGuard automatically detects supported manifests.
2.  **Automatic Scan**: Scans trigger on workspace open, file changes, and saves.
3.  **Unified Results**: Use the **Shield Icon** on the Activity Bar to browse all detected risks by file and dependency.

## ⚙️ Technical Prowess
- **Zero-Dependency Architecture**: Built using pure TypeScript and the native `https` module for maximum security and lightweight footprint.
- **Performance Driven**: Intelligent local caching (1hr TTL) and batch API querying for near-instant results.
- **Privacy First**: No telemetry, no account needed, and no external calls except to official registries and the OSV.dev API.

## 📄 License
MIT
