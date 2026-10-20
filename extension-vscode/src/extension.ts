import * as vscode from 'vscode';
import * as path from 'path';
import { AgentClient, Finding } from './ipc/client';
import { DiagnosticsManager } from './diagnostics';
import { SentinelCodeActionProvider } from './codeActions';
import { FindingsTreeProvider } from './sidebar/findingsProvider';
import { SentinelStatusBar } from './statusBar';

let agentClient: AgentClient;
let diagnosticsManager: DiagnosticsManager;
let codeActionProvider: SentinelCodeActionProvider;
let treeProvider: FindingsTreeProvider;
let statusBar: SentinelStatusBar;
let currentFindings: Finding[] = [];

export function activate(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('sentinel');
    const port = config.get<number>('agentPort', 48921);

    agentClient = new AgentClient('127.0.0.1', port);
    diagnosticsManager = new DiagnosticsManager();
    codeActionProvider = new SentinelCodeActionProvider();
    treeProvider = new FindingsTreeProvider();
    statusBar = new SentinelStatusBar();

    // Register Sidebar view
    vscode.window.registerTreeDataProvider('sentinel.findings', treeProvider);

    // Register Code Action Provider
    const selector: vscode.DocumentSelector = [
        { scheme: 'file', language: '*' }
    ];
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            selector,
            codeActionProvider,
            { providedCodeActionKinds: SentinelCodeActionProvider.providedCodeActionKinds }
        )
    );

    // Register Hover Provider
    context.subscriptions.push(
        vscode.languages.registerHoverProvider(selector, {
            provideHover(document, position) {
                const line = position.line + 1;
                const relFile = path.relative(getWorkspaceRoot() || '', document.uri.fsPath).replace(/\\/g, '/');

                const matched = currentFindings.find(f => {
                    const fRel = f.file.replace(/\\/g, '/');
                    return (fRel === relFile || document.uri.fsPath.endsWith(f.file)) &&
                        line >= f.line_start && line <= f.line_end;
                });

                if (matched) {
                    const md = new vscode.MarkdownString();
                    md.appendMarkdown(`### 🛡️ Sentinel: ${matched.rule}\n\n`);
                    const engineLabel = matched.engine === 'embedded' ? '⚡ Embedded Lite Engine' : '🔬 External Tool (Production)';
                    md.appendMarkdown(`**Engine:** \`${engineLabel}\`\n\n`);
                    md.appendMarkdown(`**Severity:** \`${matched.severity.toUpperCase()}\` | **Category:** \`${matched.category}\` | **Risk Score:** \`${matched.risk_score}/100\`\n\n`);
                    md.appendMarkdown(`${matched.message}\n\n`);
                    if (matched.cwe) {
                        md.appendMarkdown(`[View ${matched.cwe} Advisory](https://cwe.mitre.org/data/definitions/${matched.cwe.replace(/^CWE-/, '')}.html)\n\n`);
                    }
                    if (matched.fix_suggestion) {
                        md.appendMarkdown(`💡 **Quick Fix:** *${matched.fix_suggestion.description}*\n`);
                    }
                    return new vscode.Hover(md);
                }
                return null;
            }
        })
    );

    // Trust & Local-first privacy notice
    const hasShownBanner = context.globalState.get<boolean>('sentinel.trustBannerShown', false);
    if (!hasShownBanner) {
        vscode.window.showInformationMessage(
            '🛡️ Sentinel is active: All SAST, SCA, and secrets scans execute 100% locally on your machine. Zero code leaves your environment.',
            'Got it'
        ).then(() => {
            context.globalState.update('sentinel.trustBannerShown', true);
        });
    }

    // Register Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.scanWorkspace', async () => {
            await runScan(false);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.scanFile', async () => {
            const editor = vscode.window.activeTextEditor;
            if (!editor) {
                vscode.window.showWarningMessage('No active file to scan.');
                return;
            }
            const rel = path.relative(getWorkspaceRoot() || '', editor.document.uri.fsPath);
            await runScan(true, [rel]);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.showFindingDetails', (findingId: string) => {
            const f = currentFindings.find(item => item.id === findingId);
            if (!f) return;

            vscode.window.showInformationMessage(
                `[${f.severity.toUpperCase()}] ${f.rule}: ${f.message}`,
                'View Rule'
            ).then(choice => {
                if (choice === 'View Rule' && f.cwe) {
                    vscode.env.openExternal(vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${f.cwe.replace(/^CWE-/, '')}.html`));
                }
            });
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.applyFix', async (findingId: string) => {
            const root = getWorkspaceRoot();
            if (!root) return;

            try {
                const preview = await agentClient.previewFix(root, findingId);
                const confirm = await vscode.window.showInformationMessage(
                    `Apply fix for ${findingId}?\n${preview.description}`,
                    { modal: true, detail: preview.diff || 'Automatic code replacement' },
                    'Apply Fix'
                );

                if (confirm === 'Apply Fix') {
                    const result = await agentClient.applyFix(root, findingId);
                    if (result.success) {
                        vscode.window.showInformationMessage(`✅ Fix applied successfully.`);
                        // Re-scan to update squiggles
                        await runScan(true);
                    }
                }
            } catch (err: any) {
                vscode.window.showErrorMessage(`Failed to apply fix: ${err.message}`);
            }
        })
    );

    // On-save incremental trigger
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            const scanOnSave = vscode.workspace.getConfiguration('sentinel').get<boolean>('scanOnSave', true);
            if (scanOnSave && !doc.uri.fsPath.includes('.git')) {
                const root = getWorkspaceRoot();
                if (root) {
                    const rel = path.relative(root, doc.uri.fsPath);
                    await runScan(true, [rel]);
                }
            }
        })
    );

    // Initial passive scan
    runScan(false);
}

async function runScan(incremental: boolean, paths: string[] = []) {
    const root = getWorkspaceRoot();
    if (!root) return;

    statusBar.setScanning();

    try {
        const scanId = await agentClient.scanRun(root, paths, incremental);

        // Poll status
        let attempts = 0;
        const interval = setInterval(async () => {
            attempts++;
            try {
                const status = await agentClient.scanStatus(scanId);
                if (status.state === 'done') {
                    clearInterval(interval);
                    currentFindings = await agentClient.getFindings(scanId);

                    diagnosticsManager.updateDiagnostics(root, currentFindings);
                    codeActionProvider.setFindings(currentFindings);
                    treeProvider.refresh(currentFindings, root);
                    statusBar.setResults(currentFindings);
                } else if (status.state === 'error' || attempts > 20) {
                    clearInterval(interval);
                    statusBar.setIdle();
                }
            } catch (e) {
                clearInterval(interval);
                statusBar.setIdle();
            }
        }, 500);

    } catch (err: any) {
        // sentinel-agent not running or socket unavailable
        statusBar.setIdle();
    }
}

function getWorkspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
        ? vscode.workspace.workspaceFolders[0].uri.fsPath
        : undefined;
}

export function deactivate() {
    diagnosticsManager.dispose();
    statusBar.dispose();
}
