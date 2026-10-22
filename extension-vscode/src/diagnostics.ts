import * as vscode from 'vscode';
import * as path from 'path';
import { Finding } from './ipc/client';

export class DiagnosticsManager {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('sentinel');
    }

    public updateDiagnostics(workspaceRoot: string, findings: Finding[]): void {
        this.diagnosticCollection.clear();

        const fileFindingsMap = new Map<string, Finding[]>();

        for (const finding of findings) {
            const absolutePath = path.isAbsolute(finding.file)
                ? finding.file
                : path.join(workspaceRoot, finding.file);

            const list = fileFindingsMap.get(absolutePath) || [];
            list.push(finding);
            fileFindingsMap.set(absolutePath, list);
        }

        const config = vscode.workspace.getConfiguration('sentinel');
        const minSev = config.get<string>('severityFilter', 'all').toLowerCase();

        const sevRank: Record<string, number> = {
            low: 1,
            medium: 2,
            high: 3,
            critical: 4
        };
        const minRank = sevRank[minSev] || 0;

        for (const [filePath, fileFindings] of fileFindingsMap.entries()) {
            const uri = vscode.Uri.file(filePath);
            const diagnostics: vscode.Diagnostic[] = [];

            for (const f of fileFindings) {
                const fRank = sevRank[f.severity.toLowerCase()] || 0;
                if (minRank > 0 && fRank < minRank) {
                    continue;
                }

                const line = Math.max(0, f.line_start - 1);
                const range = new vscode.Range(line, 0, line, 120);

                let severity = vscode.DiagnosticSeverity.Warning;
                switch (f.severity.toLowerCase()) {
                    case 'critical':
                    case 'high':
                        severity = vscode.DiagnosticSeverity.Error;
                        break;
                    case 'medium':
                        severity = vscode.DiagnosticSeverity.Warning;
                        break;
                    case 'low':
                    case 'info':
                        severity = vscode.DiagnosticSeverity.Information;
                        break;
                }

                const engineLabel = f.engine ? ` (${f.engine})` : '';
                const msg = `[Sentinel ${f.category.toUpperCase()}${engineLabel}] ${f.message} (Risk: ${f.risk_score}/100, Rule: ${f.rule})`;
                const diagnostic = new vscode.Diagnostic(range, msg, severity);
                diagnostic.code = f.id;
                diagnostic.source = f.engine === 'embedded' ? 'Sentinel (Lite)' : 'Sentinel';

                if (f.cwe) {
                    const cweId = f.cwe.replace(/^CWE-/, '');
                    diagnostic.code = {
                        value: f.id,
                        target: vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${cweId}.html`)
                    };
                }

                diagnostics.push(diagnostic);
            }

            this.diagnosticCollection.set(uri, diagnostics);
        }
    }

    public clear(): void {
        this.diagnosticCollection.clear();
    }

    public dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
