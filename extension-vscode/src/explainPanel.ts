import * as vscode from 'vscode';
import { Finding } from './ipc/client';

export class ExplainPanel {
    public static currentPanel: ExplainPanel | undefined;
    private readonly panel: vscode.WebviewPanel;
    private disposables: vscode.Disposable[] = [];

    public static show(extensionUri: vscode.Uri, finding: Finding, workspaceRoot: string) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (ExplainPanel.currentPanel) {
            ExplainPanel.currentPanel.panel.reveal(column);
            ExplainPanel.currentPanel.update(finding, workspaceRoot);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            'sentinelExplain',
            `Sentinel: ${finding.rule}`,
            column || vscode.ViewColumn.Beside,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [extensionUri]
            }
        );

        ExplainPanel.currentPanel = new ExplainPanel(panel, finding, workspaceRoot);
    }

    private constructor(panel: vscode.WebviewPanel, finding: Finding, workspaceRoot: string) {
        this.panel = panel;

        this.panel.onDidDispose(() => this.dispose(), null, this.disposables);

        this.panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'applyFix':
                        vscode.commands.executeCommand('sentinel.applyFix', message.findingId);
                        return;
                    case 'suppressFinding':
                        vscode.commands.executeCommand('sentinel.suppressFinding', message.findingId);
                        return;
                    case 'openFile':
                        if (message.file) {
                            const uri = vscode.Uri.file(message.file);
                            vscode.workspace.openTextDocument(uri).then(doc => {
                                vscode.window.showTextDocument(doc, {
                                    selection: new vscode.Range(
                                        Math.max(0, (message.line || 1) - 1),
                                        0,
                                        Math.max(0, (message.line || 1) - 1),
                                        120
                                    )
                                });
                            });
                        }
                        return;
                }
            },
            null,
            this.disposables
        );

        this.update(finding, workspaceRoot);
    }

    public update(finding: Finding, workspaceRoot: string) {
        this.panel.title = `Sentinel: ${escapeHtml(finding.rule)}`;
        this.panel.webview.html = this.getHtmlForWebview(finding, workspaceRoot);
    }

    public dispose() {
        ExplainPanel.currentPanel = undefined;
        this.panel.dispose();
        while (this.disposables.length) {
            const x = this.disposables.pop();
            if (x) {
                x.dispose();
            }
        }
    }

    private getHtmlForWebview(finding: Finding, workspaceRoot: string): string {
        const sev = escapeHtml(finding.severity.toUpperCase());
        const category = escapeHtml(finding.category.toUpperCase());
        const rule = escapeHtml(finding.rule);
        const message = escapeHtml(finding.message);
        const file = escapeHtml(finding.file);
        const line = finding.line_start;
        const riskScore = finding.risk_score;
        const cwe = finding.cwe ? escapeHtml(finding.cwe) : '';
        const cve = finding.cve ? escapeHtml(finding.cve) : '';
        const engineLabel = finding.engine === 'embedded' ? 'Embedded Lite Engine' : 'External CLI Engine (Production)';

        let sevColor = '#eab308'; // medium
        if (finding.severity.toLowerCase() === 'critical') sevColor = '#dc2626';
        if (finding.severity.toLowerCase() === 'high') sevColor = '#ef4444';
        if (finding.severity.toLowerCase() === 'low') sevColor = '#3b82f6';

        let cweLink = '';
        if (cwe) {
            const cweNum = cwe.replace(/^CWE-/, '');
            cweLink = `<a href="https://cwe.mitre.org/data/definitions/${cweNum}.html" target="_blank" style="color: #60a5fa; text-decoration: none;">📘 ${cwe} Advisory</a>`;
        }

        let fixHtml = '';
        if (finding.fix_suggestion) {
            const fixDesc = escapeHtml(finding.fix_suggestion.description);
            const fixDiff = finding.fix_suggestion.diff ? escapeHtml(finding.fix_suggestion.diff) : '';
            const conf = escapeHtml(finding.fix_suggestion.confidence || 'medium');

            fixHtml = `
            <div style="margin-top: 24px; padding: 16px; background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 8px;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <h3 style="margin: 0; color: #4ade80; font-size: 15px;">💡 Suggested Remediation (${conf} confidence)</h3>
                    <button onclick="applyFix('${escapeHtml(finding.id)}')" style="background: #16a34a; color: white; border: none; padding: 6px 14px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                        Apply Fix
                    </button>
                </div>
                <p style="margin: 8px 0; color: #d1d5db; font-size: 13px;">${fixDesc}</p>
                ${fixDiff ? `<pre style="background: #111827; padding: 12px; border-radius: 6px; overflow-x: auto; color: #a7f3d0; font-family: monospace; font-size: 12px; border: 1px solid #374151;">${fixDiff}</pre>` : ''}
            </div>
            `;
        }

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Finding Explanation</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            color: var(--vscode-editor-foreground, #cccccc);
            background: var(--vscode-editor-background, #1e1e1e);
            padding: 24px;
            line-height: 1.5;
        }
        .badge {
            display: inline-block;
            padding: 2px 10px;
            font-size: 12px;
            font-weight: bold;
            border-radius: 4px;
            color: #ffffff;
            margin-right: 8px;
        }
        .meta-table {
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            background: var(--vscode-sideBar-background, #252526);
            border-radius: 6px;
            overflow: hidden;
        }
        .meta-table td {
            padding: 8px 14px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            font-size: 13px;
        }
        .meta-table td:first-child {
            color: #9ca3af;
            width: 140px;
            font-weight: 500;
        }
        .btn-secondary {
            background: transparent;
            color: #9ca3af;
            border: 1px solid #4b5563;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-right: 8px;
        }
        .btn-secondary:hover {
            color: white;
            border-color: #9ca3af;
        }
    </style>
</head>
<body>
    <div style="display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 16px;">
        <div>
            <span class="badge" style="background: ${sevColor};">${sev}</span>
            <span class="badge" style="background: #4b5563;">${category}</span>
            <span class="badge" style="background: #374151;">Risk Score: ${riskScore}/100</span>
            <h2 style="margin: 8px 0 0 0; color: #f3f4f6;">${rule}</h2>
        </div>
        <div>
            <button class="btn-secondary" onclick="suppressFinding('${escapeHtml(finding.id)}')">Suppress Finding</button>
        </div>
    </div>

    <table class="meta-table">
        <tr>
            <td>Engine Provenance</td>
            <td><strong>${engineLabel}</strong></td>
        </tr>
        <tr>
            <td>Location</td>
            <td>
                <a href="#" onclick="openFile('${file}', ${line})" style="color: #60a5fa; text-decoration: none;">
                    ${file}:${line}
                </a>
            </td>
        </tr>
        ${cweLink ? `<tr><td>Classification</td><td>${cweLink}</td></tr>` : ''}
        ${cve ? `<tr><td>CVE Identifier</td><td><code>${cve}</code></td></tr>` : ''}
    </table>

    <div style="margin-top: 20px;">
        <h3 style="color: #e5e7eb; font-size: 14px; margin-bottom: 8px;">Vulnerability Description</h3>
        <p style="background: var(--vscode-sideBar-background, #252526); padding: 14px; border-radius: 6px; font-size: 13px; margin: 0; border-left: 3px solid ${sevColor};">
            ${message}
        </p>
    </div>

    ${fixHtml}

    <div style="margin-top: 24px; padding: 14px; background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 6px; font-size: 12px; color: #9ca3af;">
        🛡️ <strong>Sentinel Privacy Guarantee:</strong> This analysis was performed locally in your development workspace. No source code or confidential telemetry was transmitted to external servers.
    </div>

    <script>
        const vscode = acquireVsCodeApi();
        function applyFix(findingId) {
            vscode.postMessage({ command: 'applyFix', findingId: findingId });
        }
        function suppressFinding(findingId) {
            vscode.postMessage({ command: 'suppressFinding', findingId: findingId });
        }
        function openFile(file, line) {
            vscode.postMessage({ command: 'openFile', file: file, line: line });
        }
    </script>
</body>
</html>`;
    }
}

function escapeHtml(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
