import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as cp from 'child_process';
import { AgentClient, Finding } from './ipc/client';
import { DiagnosticsManager } from './diagnostics';
import { SentinelCodeActionProvider } from './codeActions';
import { FindingsTreeProvider } from './sidebar/findingsProvider';
import { SentinelStatusBar } from './statusBar';
import { ExplainPanel } from './explainPanel';

let agentClient: AgentClient;
let diagnosticsManager: DiagnosticsManager;
let codeActionProvider: SentinelCodeActionProvider;
let treeProvider: FindingsTreeProvider;
let statusBar: SentinelStatusBar;
let outputChannel: vscode.OutputChannel;
let agentProcess: cp.ChildProcess | undefined;
let currentFindings: Finding[] = [];
let saveTimeout: NodeJS.Timeout | undefined;

function redactSecrets(text: string): string {
    return text.replace(/(token|key|password|secret|bearer)\s*[:=]\s*["']?([^"'\s]+)["']?/gi, '$1=[REDACTED]');
}

function logInfo(msg: string) {
    outputChannel.appendLine(`[INFO  ${new Date().toISOString()}] ${redactSecrets(msg)}`);
}

function logWarn(msg: string) {
    outputChannel.appendLine(`[WARN  ${new Date().toISOString()}] ${redactSecrets(msg)}`);
}

function logError(msg: string) {
    outputChannel.appendLine(`[ERROR ${new Date().toISOString()}] ${redactSecrets(msg)}`);
}

export async function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('Sentinel Security');
    context.subscriptions.push(outputChannel);
    logInfo('Sentinel DevSecOps extension activating...');

    const config = vscode.workspace.getConfiguration('sentinel');
    const port = config.get<number>('agentPort', 48921);
    const configuredBinary = config.get<string>('binaryPath', '');

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
                const root = getWorkspaceRoot() || '';
                const relFile = path.relative(root, document.uri.fsPath).replace(/\\/g, '/');

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
                        md.appendMarkdown(`💡 **Quick Fix:** *${matched.fix_suggestion.description}*\n\n`);
                    }
                    md.appendMarkdown(`[Explain Finding](command:sentinel.showFindingDetails?${encodeURIComponent(JSON.stringify(matched.id))})`);
                    md.isTrusted = true;
                    return new vscode.Hover(md);
                }
                return null;
            }
        })
    );

    // Workspace Trust enforcement (T-121)
    if (!vscode.workspace.isTrusted) {
        logWarn('Workspace is untrusted. Sentinel scanning is disabled until trust is granted.');
        vscode.workspace.onDidGrantWorkspaceTrust(() => {
            logInfo('Workspace trust granted. Initializing Sentinel...');
            initAgentAndScan(context, port, configuredBinary);
        }, null, context.subscriptions);
        return;
    }

    // Trust banner (T-121)
    const hasShownBanner = context.globalState.get<boolean>('sentinel.trustBannerShown', false);
    if (!hasShownBanner) {
        vscode.window.showInformationMessage(
            '🛡️ Sentinel is active: All SAST, SCA, and secrets scans execute 100% locally on your machine. Zero code leaves your environment.',
            'Got it'
        ).then(() => {
            context.globalState.update('sentinel.trustBannerShown', true);
        });
    }

    // Register all Contributed Commands (T-119)
    registerCommands(context);

    // Register on-save incremental scan with debounce (T-122)
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(async (doc) => {
            const currentCfg = vscode.workspace.getConfiguration('sentinel');
            const scanOnSave = currentCfg.get<boolean>('scanOnSave', true);
            const debounceMs = currentCfg.get<number>('debounceMs', 500);

            if (!scanOnSave) return;
            const fsPath = doc.uri.fsPath;
            if (fsPath.includes('.git') || fsPath.includes('node_modules') || fsPath.includes('dist')) {
                return;
            }

            if (saveTimeout) {
                clearTimeout(saveTimeout);
            }

            saveTimeout = setTimeout(async () => {
                const root = getWorkspaceRoot();
                if (root && vscode.workspace.isTrusted) {
                    const rel = path.relative(root, fsPath);
                    logInfo(`Incremental scan triggered on save for: ${rel}`);
                    await runScan(true, [rel]);
                }
            }, debounceMs);
        })
    );

    // Lifecycle: ensure agent is running, then passive initial scan
    await initAgentAndScan(context, port, configuredBinary);
}

async function initAgentAndScan(context: vscode.ExtensionContext, port: number, binaryPath?: string) {
    const isRunning = await ensureAgentLifecycle(port, binaryPath);
    if (isRunning) {
        logInfo('Agent connection verified. Initiating baseline scan.');
        await runScan(false);
    } else {
        logWarn('Running in standalone mode: agent IPC daemon not available.');
        statusBar.setIdle();
    }
}

async function ensureAgentLifecycle(port: number, configuredBinary?: string): Promise<boolean> {
    try {
        const ping = await agentClient.ping();
        if (ping.status === 'ok') {
            logInfo(`Connected to active sentinel-agent IPC daemon (v${ping.version}) on port ${port}.`);
            return true;
        }
    } catch {
        // Agent not running, attempt to locate and spawn binary
    }

    const candidatePaths = [
        configuredBinary,
        path.join(getWorkspaceRoot() || '', 'bin', process.platform === 'win32' ? 'sentinel-agent.exe' : 'sentinel-agent'),
        path.join(getWorkspaceRoot() || '', 'bin', process.platform === 'win32' ? 'sentinel.exe' : 'sentinel'),
        'sentinel-agent',
        'sentinel'
    ].filter(Boolean) as string[];

    for (const bin of candidatePaths) {
        try {
            if (fs.existsSync(bin) || !bin.includes(path.sep)) {
                logInfo(`Attempting to launch agent daemon from: ${bin}`);
                agentProcess = cp.spawn(bin, ['--port', String(port)], {
                    detached: false,
                    stdio: 'ignore'
                });
                agentProcess.on('error', (err) => {
                    logWarn(`Failed to start agent from ${bin}: ${err.message}`);
                });

                // Wait up to 2 seconds for port to open
                for (let i = 0; i < 8; i++) {
                    await new Promise(r => setTimeout(r, 250));
                    try {
                        const ping = await agentClient.ping();
                        if (ping.status === 'ok') {
                            logInfo(`Successfully started sentinel-agent daemon on port ${port}.`);
                            return true;
                        }
                    } catch {}
                }
            }
        } catch {}
    }

    logWarn(`Could not automatically launch sentinel-agent. Please run 'sentinel-agent --port ${port}' or install Sentinel.`);
    return false;
}

function registerCommands(context: vscode.ExtensionContext) {
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.scanWorkspace', async () => {
            logInfo('Command: sentinel.scanWorkspace');
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
            const root = getWorkspaceRoot() || '';
            const rel = path.relative(root, editor.document.uri.fsPath);
            logInfo(`Command: sentinel.scanFile (${rel})`);
            await runScan(true, [rel]);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.showFindingDetails', (findingId: string) => {
            const f = currentFindings.find(item => item.id === findingId);
            if (!f) return;
            const root = getWorkspaceRoot() || '';
            ExplainPanel.show(context.extensionUri, f, root);
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
                    { modal: true, detail: preview.diff || 'Automatic code remediation' },
                    'Apply Fix'
                );

                if (confirm === 'Apply Fix') {
                    const result = await agentClient.applyFix(root, findingId);
                    if (result.success) {
                        vscode.window.showInformationMessage(`✅ Fix applied successfully.`);
                        logInfo(`Applied automated fix for ${findingId}`);
                        await runScan(true);
                    }
                }
            } catch (err: any) {
                vscode.window.showErrorMessage(`Failed to apply fix: ${err.message}`);
                logError(`Failed to apply fix for ${findingId}: ${err.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.threatModel', async () => {
            const root = getWorkspaceRoot();
            if (!root) return;

            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: 'Sentinel: Mapping STRIDE Threat Model...',
                cancellable: false
            }, async () => {
                try {
                    const tm = await agentClient.runThreatModel(root);
                    logInfo(`Generated threat model for ${root}`);
                    const doc = await vscode.workspace.openTextDocument({
                        content: tm.markdown || JSON.stringify(tm, null, 2),
                        language: 'markdown'
                    });
                    await vscode.window.showTextDocument(doc);
                } catch (err: any) {
                    vscode.window.showErrorMessage(`Threat model generation failed: ${err.message}`);
                    logError(`Threat model error: ${err.message}`);
                }
            });
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.sbom', async () => {
            const root = getWorkspaceRoot();
            if (!root) return;

            const format = await vscode.window.showQuickPick(['cyclonedx', 'spdx'], {
                placeHolder: 'Select SBOM standard format'
            });
            if (!format) return;

            const out = path.join(root, `sbom.${format}.json`);
            try {
                await agentClient.generateSBOM(root, format, out);
                vscode.window.showInformationMessage(`✅ SBOM generated: ${out}`);
                logInfo(`Generated ${format} SBOM: ${out}`);
            } catch (err: any) {
                vscode.window.showErrorMessage(`SBOM generation failed: ${err.message}`);
                logError(`SBOM error: ${err.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.doctor', async () => {
            try {
                const statuses = await agentClient.runDoctor();
                outputChannel.show();
                logInfo('=== Sentinel Engine Diagnostics (Doctor) ===');
                for (const st of statuses) {
                    const icon = st.Found ? '✅' : '❌';
                    logInfo(`${icon} ${st.Name} [${st.Mode}]: ${st.Version || 'Missing'}`);
                    if (!st.Found && st.Recommended) {
                        logInfo(`   💡 Recommendation: ${st.Recommended}`);
                    }
                }
                vscode.window.showInformationMessage(`Sentinel Doctor: ${statuses.filter(s => s.Found).length}/${statuses.length} scanning engines available.`);
            } catch (err: any) {
                vscode.window.showErrorMessage(`Doctor check failed: ${err.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.createBaseline', async () => {
            const root = getWorkspaceRoot();
            if (!root) return;

            try {
                const res = await agentClient.createBaseline(root);
                vscode.window.showInformationMessage(`✅ Accepted ${res.count} findings into baseline.`);
                logInfo(`Accepted ${res.count} findings into baseline file: ${res.path}`);
                await runScan(false);
            } catch (err: any) {
                vscode.window.showErrorMessage(`Failed to create baseline: ${err.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.suppressFinding', async (findingId?: string) => {
            const root = getWorkspaceRoot();
            if (!root) return;

            if (!findingId) {
                findingId = await vscode.window.showInputBox({
                    prompt: 'Enter finding ID to suppress',
                    placeHolder: 'e.g. SEC-001 or CWE-89'
                });
            }
            if (!findingId) return;

            const reason = await vscode.window.showInputBox({
                prompt: `Mandatory reason for suppressing ${findingId}`,
                placeHolder: 'e.g. False positive verified by AppSec team'
            });
            if (!reason) {
                vscode.window.showWarningMessage('Suppression cancelled: justification reason is mandatory.');
                return;
            }

            const expires = await vscode.window.showInputBox({
                prompt: 'Optional expiration date (YYYY-MM-DD)',
                placeHolder: 'Leave blank for permanent suppression'
            });

            try {
                const res = await agentClient.addSuppression(root, findingId, reason, expires);
                vscode.window.showInformationMessage(`✅ Finding ${findingId} suppressed in ${path.basename(res.file)}.`);
                logInfo(`Suppressed finding ${findingId} (Reason: ${reason})`);
                await runScan(true);
            } catch (err: any) {
                vscode.window.showErrorMessage(`Failed to suppress finding: ${err.message}`);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.openReport', async () => {
            const root = getWorkspaceRoot();
            if (!root) return;
            const reportPath = path.join(root, 'sentinel-report.html');
            if (fs.existsSync(reportPath)) {
                vscode.env.openExternal(vscode.Uri.file(reportPath));
            } else {
                vscode.window.showInformationMessage('Run Sentinel CLI with --format html --out sentinel-report.html to create a standalone HTML report.');
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.dastScan', async () => {
            const target = await vscode.window.showInputBox({
                prompt: 'Enter authorized target URL for DAST scan',
                placeHolder: 'https://staging.example.com'
            });
            if (!target) return;

            const auth = await vscode.window.showWarningMessage(
                `DAST scans send real HTTP security payloads to ${target}.\nDo you have explicit legal authorization to test this target?`,
                { modal: true },
                'Yes, I have authorization'
            );
            if (auth !== 'Yes, I have authorization') {
                vscode.window.showWarningMessage('DAST scan cancelled: authorization required.');
                return;
            }

            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: `Running DAST scan against ${target}...`,
                cancellable: false
            }, async () => {
                try {
                    const findings = await agentClient.runDAST(target, true);
                    logInfo(`DAST scan complete against ${target}: ${findings.length} findings.`);
                    vscode.window.showInformationMessage(`DAST Scan finished: ${findings.length} findings detected.`);
                } catch (err: any) {
                    vscode.window.showErrorMessage(`DAST scan failed: ${err.message}`);
                }
            });
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.toggleSidebarGrouping', () => {
            const newMode = treeProvider.toggleGrouping();
            vscode.window.showInformationMessage(`Findings grouped by: ${newMode.toUpperCase()}`);
        })
    );
}

async function runScan(incremental: boolean, paths: string[] = []) {
    const root = getWorkspaceRoot();
    if (!root || !vscode.workspace.isTrusted) return;

    statusBar.setScanning();
    const config = vscode.workspace.getConfiguration('sentinel');
    const offline = config.get<boolean>('offline', false);
    const policyPath = config.get<string>('policyPath', '');

    try {
        const scanId = await agentClient.scanRun(root, paths, incremental, offline, policyPath || undefined);
        logInfo(`Initiated scan ID: ${scanId} (incremental: ${incremental})`);

        let attempts = 0;
        const interval = setInterval(async () => {
            attempts++;
            try {
                const status = await agentClient.scanStatus(scanId);
                if (status.state === 'done') {
                    clearInterval(interval);
                    currentFindings = await agentClient.getFindings(scanId);
                    logInfo(`Scan ${scanId} completed with ${currentFindings.length} findings.`);

                    let coverageInfo = null;
                    try {
                        coverageInfo = await agentClient.getCoverage();
                    } catch {}

                    diagnosticsManager.updateDiagnostics(root, currentFindings);
                    codeActionProvider.setFindings(currentFindings);
                    treeProvider.refresh(currentFindings, root, coverageInfo);
                    statusBar.setResults(currentFindings);
                } else if (status.state === 'error' || attempts > 60) {
                    clearInterval(interval);
                    logError(`Scan ${scanId} failed or timed out.`);
                    statusBar.setError('Scan timed out or error');
                }
            } catch (e: any) {
                clearInterval(interval);
                logError(`Scan polling error: ${e.message}`);
                statusBar.setError(e.message);
            }
        }, 500);

    } catch (err: any) {
        logWarn(`Agent IPC call failed: ${err.message}`);
        statusBar.setError('Agent offline');
    }
}

function getWorkspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
        ? vscode.workspace.workspaceFolders[0].uri.fsPath
        : undefined;
}

export function deactivate() {
    if (agentProcess) {
        try {
            agentProcess.kill();
        } catch {}
    }
    diagnosticsManager.dispose();
    statusBar.dispose();
    if (saveTimeout) {
        clearTimeout(saveTimeout);
    }
}
