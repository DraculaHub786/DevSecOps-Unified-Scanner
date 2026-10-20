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

        for (const [filePath, fileFindings] of fileFindingsMap.entries()) {
            const uri = vscode.Uri.file(filePath);
            const diagnostics: vscode.Diagnostic[] = [];

            for (const f of fileFindings) {
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

                const msg = `[Sentinel ${f.category.toUpperCase()}] ${f.message} (Risk: ${f.risk_score}/100, Rule: ${f.rule})`;
                const diagnostic = new vscode.Diagnostic(range, msg, severity);
                diagnostic.code = f.id;
                diagnostic.source = 'Sentinel';

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
