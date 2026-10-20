import * as vscode from 'vscode';
import { Finding } from './ipc/client';

export class SentinelCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    private findingsMap: Map<string, Finding> = new Map();

    public setFindings(findings: Finding[]) {
        this.findingsMap.clear();
        for (const f of findings) {
            this.findingsMap.set(f.id, f);
        }
    }

    public provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.CodeAction[] {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'Sentinel') {
                continue;
            }

            const findingId = typeof diagnostic.code === 'object'
                ? String(diagnostic.code.value)
                : String(diagnostic.code);

            const finding = this.findingsMap.get(findingId);
            if (!finding) {
                continue;
            }

            // Quick Fix action
            if (finding.fix_suggestion) {
                const fixAction = new vscode.CodeAction(
                    `Sentinel: Apply suggested fix (${finding.fix_suggestion.description})`,
                    vscode.CodeActionKind.QuickFix
                );
                fixAction.command = {
                    command: 'sentinel.applyFix',
                    title: 'Apply Suggested Fix',
                    arguments: [finding.id]
                };
                fixAction.diagnostics = [diagnostic];
                fixAction.isPreferred = true;
                actions.push(fixAction);
            }

            // Explain Action
            const explainAction = new vscode.CodeAction(
                `Sentinel: Explain security flaw (${finding.rule})`,
                vscode.CodeActionKind.QuickFix
            );
            explainAction.command = {
                command: 'sentinel.showFindingDetails',
                title: 'Explain Finding',
                arguments: [finding.id]
            };
            explainAction.diagnostics = [diagnostic];
            actions.push(explainAction);
        }

        return actions;
    }
}
