# SupplyGuard - Universal Dependency Vulnerability Checker 🛡️

## 📸 See it in action
![SupplyGuard Scan Demo](https://i.ibb.co/m51KPwJJ/0404.gif)

![Vulnerability Diagnostics Example](https://i.ibb.co/VF6DGyz/2220404.gif)

![Shield Sidebar and Problems Panel](https://i.ibb.co/1f2NMKp9/54454.gif)


## 🤔 Why SupplyGuard?

- **Continuous Automation** - Most developers forget to run `npm audit` until it's too late. SupplyGuard is an **Invisible Shield** that scans your project automatically on every file change.
- **Beyond the Database** - Traditional scanners like `npm audit` are **reactive**—they only flag what's already reported. SupplyGuard is **proactive**, using a **Zero-Day Radar** to flag suspicious brand-new updates *before* they appear in any database.

## 🚀 Key Features

### 🚨 Zero-Day Supply-Chain Radar
Identifies packages published within the last **48 hours**. This is a critical indicator of potential supply-chain attacks (like the recent axios malicious release). 

### 🔍 Multi-Ecosystem OSV.dev Integration
Comprehensive security scanning using the OSV batch API for maximum performance.
- **Node.js** - `npm`, `pnpm`, `yarn`, `bun` (`package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`)
- **Python** - `requirements.txt`, `pyproject.toml`, `Pipfile`
- **Go** - `go.mod`
- **Rust** - `Cargo.toml`
- **Java** - `pom.xml` (Maven/Gradle support coming soon!)

### 🛠️ Polished UX & Integration
- **Inline Diagnostics** - Visual highlights and error messages directly in your manifest files.
- **Shield Sidebar** - A dedicated Activity Bar view containing the full vulnerability tree.
- **Problems Panel** - Native integration for easy navigation between risks.
- **Status Bar Indicator** - Real-time project security status at a glance.

## 🛠️ Installation & Usage
1.  **Open any project** - SupplyGuard automatically detects supported manifests.
2.  **Automatic Scan** - Scans trigger on workspace open, file changes, and saves.
3.  **Unified Results** - Use the **Shield Icon** on the Activity Bar to browse all detected risks by file and dependency.

## ⚙️ Custom Manual Database (`supplyguard.json`)

If a vulnerability is not yet in OSV.dev, you can manually flag it by creating a `supplyguard.json` file in your project root:

```json
{
  "database": [
    {
      "package": "lodash",
      "ecosystem": "npm",
      "version": "4.17.21",
      "vulnerabilities": [
        {
          "id": "SG-MANUAL-001",
          "summary": "Internal Security Flag",
          "details": "This version is restricted by company policy.",
          "severity": "CRITICAL"
        }
      ]
    }
  ]
}
```

## ⚙️ Technical Prowess
- **Zero-Dependency Architecture** - Built using pure TypeScript and the native `https` module for maximum security and lightweight footprint.
- **Performance Driven** - Intelligent local caching (1hr TTL) and batch API querying for near-instant results.
- **Privacy First** - No telemetry, no account needed, and no external calls except to official registries and the OSV.dev API.

## 📄 License
MIT
