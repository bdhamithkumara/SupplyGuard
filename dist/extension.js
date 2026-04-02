"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
const vscode = __importStar(require("vscode"));
const https = __importStar(require("https"));
const path = __importStar(require("path"));
const SUPPORTED_FILES = {
    'package.json': 'npm',
    'package-lock.json': 'npm',
    'requirements.txt': 'PyPI',
    'pyproject.toml': 'PyPI',
    'Pipfile': 'PyPI',
    'Pipfile.lock': 'PyPI',
    'pom.xml': 'Maven',
    'build.gradle': 'Maven',
    'build.gradle.kts': 'Maven',
    'go.mod': 'Go',
    'Cargo.toml': 'Cargo'
};
function activate(context) {
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('SupplyGuard');
    const scanner = new VulnerabilityScanner(context, diagnosticCollection);
    // Initial scan
    scanner.scanWorkspace();
    // Register commands
    context.subscriptions.push(vscode.commands.registerCommand('supplyguard.scan', () => {
        scanner.scanWorkspace(true);
    }), vscode.commands.registerCommand('supplyguard.openOsv', (vulnId) => {
        vscode.env.openExternal(vscode.Uri.parse(`https://osv.dev/vulnerability/${vulnId}`));
    }));
    // Listen for file changes
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(doc => {
        if (isSupportedFile(doc.fileName)) {
            scanner.scanFile(doc);
        }
    }), vscode.workspace.onDidOpenTextDocument(doc => {
        if (isSupportedFile(doc.fileName)) {
            scanner.scanFile(doc);
        }
    }));
    // Tree View
    const treeDataProvider = new SupplyGuardTreeDataProvider(scanner);
    context.subscriptions.push(vscode.window.registerTreeDataProvider('supplyguard-view', treeDataProvider));
    // Status Bar
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'supplyguard.scan';
    context.subscriptions.push(statusBarItem);
    scanner.setStatusBar(statusBarItem);
}
function isSupportedFile(filePath) {
    const fileName = path.basename(filePath);
    return fileName in SUPPORTED_FILES;
}
class VulnerabilityScanner {
    context;
    diagnostics;
    results = new Map();
    statusBar;
    cache = new Map();
    CACHE_TTL = 3600000; // 1 hour
    constructor(context, diagnostics) {
        this.context = context;
        this.diagnostics = diagnostics;
    }
    setStatusBar(item) {
        this.statusBar = item;
        this.updateStatusBar();
    }
    async scanWorkspace(force = false) {
        if (!vscode.workspace.workspaceFolders)
            return;
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "SupplyGuard: Scanning dependencies...",
            cancellable: false
        }, async (progress) => {
            const files = await vscode.workspace.findFiles('**/{package.json,requirements.txt,pom.xml,go.mod,Cargo.toml,pyproject.toml}');
            for (let i = 0; i < files.length; i++) {
                const doc = await vscode.workspace.openTextDocument(files[i]);
                await this.scanFile(doc, force);
                progress.report({ increment: (100 / files.length), message: `Checking ${path.basename(files[i].fsPath)}` });
            }
            this.updateStatusBar();
        });
    }
    async scanFile(doc, force = false) {
        const fileName = path.basename(doc.fileName);
        const ecosystem = SUPPORTED_FILES[fileName];
        if (!ecosystem)
            return;
        if (!force && this.cache.has(doc.fileName)) {
            const cached = this.cache.get(doc.fileName);
            if (Date.now() - cached.timestamp < this.CACHE_TTL) {
                this.updateDiagnostics(doc, cached.result);
                return;
            }
        }
        const dependencies = this.parseDependencies(doc, ecosystem);
        if (dependencies.length === 0)
            return;
        const results = await this.checkVulnerabilities(dependencies);
        this.results.set(doc.fileName, results);
        this.cache.set(doc.fileName, { result: results, timestamp: Date.now() });
        this.updateDiagnostics(doc, results);
        this.updateStatusBar();
    }
    parseDependencies(doc, ecosystem) {
        const deps = [];
        const text = doc.getText();
        const fileName = path.basename(doc.fileName);
        if (ecosystem === 'npm' && fileName === 'package.json') {
            try {
                const pkg = JSON.parse(text);
                const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
                for (const [name, version] of Object.entries(allDeps)) {
                    if (typeof version !== 'string')
                        continue;
                    // Simple version extraction (remove ^, ~, etc. for API check)
                    const cleanVersion = version.replace(/[\^~><=]/g, '').trim();
                    const line = this.findLine(text, `"${name}":`);
                    if (line !== -1) {
                        deps.push({
                            name,
                            version: cleanVersion,
                            ecosystem: 'npm',
                            file: doc.fileName,
                            range: new vscode.Range(line, 0, line, doc.lineAt(line).text.length)
                        });
                    }
                }
            }
            catch (e) { }
        }
        else if (ecosystem === 'PyPI' && fileName === 'requirements.txt') {
            const lines = text.split('\n');
            lines.forEach((line, i) => {
                const match = line.match(/^([a-zA-Z0-9\-_]+)==([a-zA-Z0-9\._\-]+)/);
                if (match) {
                    deps.push({
                        name: match[1],
                        version: match[2],
                        ecosystem: 'PyPI',
                        file: doc.fileName,
                        range: new vscode.Range(i, 0, i, line.length)
                    });
                }
            });
        }
        // Add more parsers for Go, Cargo, Maven...
        return deps;
    }
    findLine(text, search) {
        const lines = text.split('\n');
        return lines.findIndex(l => l.includes(search));
    }
    async checkVulnerabilities(deps) {
        const results = [];
        // Batch query OSV
        const osvBatch = deps.map(d => ({
            package: { name: d.name, ecosystem: d.ecosystem },
            version: d.version
        }));
        try {
            const osvData = await this.fetchJson('https://api.osv.dev/v1/querybatch', 'POST', { queries: osvBatch });
            for (let i = 0; i < deps.length; i++) {
                const dep = deps[i];
                const vulns = (osvData.results && osvData.results[i] && osvData.results[i].vulns) || [];
                let isRecent = false;
                let publishDate;
                if (dep.ecosystem === 'npm') {
                    const npmData = await this.fetchJson(`https://registry.npmjs.org/${dep.name}`, 'GET');
                    if (npmData && npmData.time && npmData.time[dep.version]) {
                        publishDate = npmData.time[dep.version];
                        const pubTime = new Date(publishDate).getTime();
                        const now = Date.now();
                        if (now - pubTime < 48 * 60 * 60 * 1000) { // 48 hours
                            isRecent = true;
                        }
                    }
                }
                else {
                    // For other ecosystems, check the "modified" date of the latest vulnerability as a proxy or just OSV modified
                    if (vulns.length > 0) {
                        const latest = new Date(vulns[0].modified).getTime();
                        if (Date.now() - latest < 48 * 60 * 60 * 1000) {
                            isRecent = true;
                        }
                    }
                }
                if (vulns.length > 0 || isRecent) {
                    results.push({
                        dependency: dep,
                        vulnerabilities: vulns.map((v) => ({
                            id: v.id,
                            summary: v.summary,
                            details: v.details,
                            modified: v.modified,
                            severity: v.database_specific?.severity || 'MODERATE'
                        })),
                        isRecent,
                        publishDate
                    });
                }
            }
        }
        catch (e) {
            console.error('SupplyGuard Scan Error:', e);
        }
        return results;
    }
    async fetchJson(url, method, body) {
        return new Promise((resolve, reject) => {
            const parsedUrl = new URL(url);
            const options = {
                hostname: parsedUrl.hostname,
                path: parsedUrl.pathname + parsedUrl.search,
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'SupplyGuard-VSCode-Extension'
                }
            };
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    }
                    catch (e) {
                        resolve({});
                    }
                });
            });
            req.on('error', (e) => reject(e));
            if (body)
                req.write(JSON.stringify(body));
            req.end();
        });
    }
    updateDiagnostics(doc, results) {
        const diagnostics = [];
        results.forEach(res => {
            let message = '';
            let severity = vscode.DiagnosticSeverity.Warning;
            if (res.isRecent) {
                message += `🚨 Possible supply-chain risk – published very recently (${new Date(res.publishDate).toLocaleString()}).\n`;
                severity = vscode.DiagnosticSeverity.Error;
            }
            if (res.vulnerabilities.length > 0) {
                message += `Vulnerabilities found: ${res.vulnerabilities.map(v => `${v.id} (${v.severity})`).join(', ')}`;
            }
            const diagnostic = new vscode.Diagnostic(res.dependency.range, message, severity);
            diagnostic.source = 'SupplyGuard';
            diagnostics.push(diagnostic);
        });
        this.diagnostics.set(doc.uri, diagnostics);
    }
    updateStatusBar() {
        if (!this.statusBar)
            return;
        let totalVulns = 0;
        this.results.forEach(res => {
            totalVulns += res.reduce((acc, curr) => acc + curr.vulnerabilities.length, 0);
        });
        if (totalVulns > 0) {
            this.statusBar.text = `$(shield) SupplyGuard: ${totalVulns} vulns`;
            this.statusBar.color = new vscode.ThemeColor('errorForeground');
            this.statusBar.show();
        }
        else {
            this.statusBar.text = `$(shield) SupplyGuard: Clear`;
            this.statusBar.color = undefined;
            this.statusBar.show();
        }
    }
    getResults() {
        return this.results;
    }
}
class SupplyGuardTreeDataProvider {
    scanner;
    _onDidChangeTreeData = new vscode.EventEmitter();
    onDidChangeTreeData = this._onDidChangeTreeData.event;
    constructor(scanner) {
        this.scanner = scanner;
        // Refresh when results change (simplified for now)
        setInterval(() => this._onDidChangeTreeData.fire(), 2000);
    }
    getTreeItem(element) {
        return element;
    }
    getChildren(element) {
        if (!element) {
            const items = [];
            this.scanner.getResults().forEach((results, filePath) => {
                if (results.length > 0) {
                    items.push(new VulnerabilityItem(path.basename(filePath), vscode.TreeItemCollapsibleState.Expanded, 'file', filePath));
                }
            });
            return Promise.resolve(items);
        }
        else if (element.contextValue === 'file') {
            const results = this.scanner.getResults().get(element.description) || [];
            return Promise.resolve(results.map(res => new VulnerabilityItem(`${res.dependency.name}@${res.dependency.version}`, vscode.TreeItemCollapsibleState.Collapsed, 'dependency', undefined, res)));
        }
        else if (element.contextValue === 'dependency' && element.result) {
            const items = [];
            if (element.result.isRecent) {
                items.push(new VulnerabilityItem("🚨 Recently Published", vscode.TreeItemCollapsibleState.None, 'info', undefined, undefined, `Supply-chain risk: Published on ${new Date(element.result.publishDate).toLocaleDateString()}`));
            }
            element.result.vulnerabilities.forEach(v => {
                items.push(new VulnerabilityItem(`${v.id}: ${v.summary || 'No summary'}`, vscode.TreeItemCollapsibleState.None, 'vulnerability', undefined, undefined, v.id));
            });
            return Promise.resolve(items);
        }
        return Promise.resolve([]);
    }
}
class VulnerabilityItem extends vscode.TreeItem {
    label;
    collapsibleState;
    contextValue;
    description;
    result;
    tooltipText;
    constructor(label, collapsibleState, contextValue, description, result, tooltipText) {
        super(label, collapsibleState);
        this.label = label;
        this.collapsibleState = collapsibleState;
        this.contextValue = contextValue;
        this.description = description;
        this.result = result;
        this.tooltipText = tooltipText;
        this.tooltip = tooltipText || label;
        if (contextValue === 'file') {
            this.iconPath = new vscode.ThemeIcon('file-code');
        }
        else if (contextValue === 'dependency') {
            this.iconPath = new vscode.ThemeIcon('package');
        }
        else if (contextValue === 'vulnerability') {
            this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('problemsErrorIcon.foreground'));
            this.command = {
                command: 'supplyguard.openOsv',
                title: 'Open in OSV',
                arguments: [this.tooltipText]
            };
        }
        else if (contextValue === 'info') {
            this.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('problemsWarningIcon.foreground'));
        }
    }
}
//# sourceMappingURL=extension.js.map