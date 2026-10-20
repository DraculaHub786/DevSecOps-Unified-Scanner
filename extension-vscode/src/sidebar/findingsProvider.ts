import * as vscode from 'vscode';
import * as path from 'path';
import { Finding } from '../ipc/client';

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<TreeItem | undefined | null | void> = new vscode.EventEmitter<TreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<TreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private findings: Finding[] = [];
    private workspaceRoot: string = '';

    public refresh(findings: Finding[], workspaceRoot: string): void {
        this.findings = findings;
        this.workspaceRoot = workspaceRoot;
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: TreeItem): Thenable<TreeItem[]> {
        if (!element) {
            // Group by Severity
            const groups = ['critical', 'high', 'medium', 'low'];
            const items: TreeItem[] = [];

            for (const sev of groups) {
                const count = this.findings.filter(f => f.severity.toLowerCase() === sev).length;
                if (count > 0) {
                    let label = `${sev.toUpperCase()} (${count})`;
                    let icon = 'error';
                    if (sev === 'critical') icon = 'flame';
                    if (sev === 'medium') icon = 'warning';
                    if (sev === 'low') icon = 'info';

                    items.push(new SeverityGroupItem(label, sev, count, icon));
                }
            }

            if (items.length === 0) {
                return Promise.resolve([new EmptyStateItem()]);
            }

            return Promise.resolve(items);
        }

        if (element instanceof SeverityGroupItem) {
            const matches = this.findings.filter(f => f.severity.toLowerCase() === element.severity);
            const items = matches.map(f => new FindingItem(f, this.workspaceRoot));
            return Promise.resolve(items);
        }

        return Promise.resolve([]);
    }
}

export abstract class TreeItem extends vscode.TreeItem {}

export class SeverityGroupItem extends TreeItem {
    constructor(
        public readonly label: string,
        public readonly severity: string,
        public readonly count: number,
        icon: string
    ) {
        super(label, vscode.TreeItemCollapsibleState.Expanded);
        this.iconPath = new vscode.ThemeIcon(icon);
    }
}

export class FindingItem extends TreeItem {
    constructor(public readonly finding: Finding, private workspaceRoot: string) {
        super(`${finding.rule}: ${finding.file}:${finding.line_start}`, vscode.TreeItemCollapsibleState.None);

        this.description = `[${finding.category}] Risk: ${finding.risk_score}`;
        this.tooltip = `${finding.message}\nCWE: ${finding.cwe || 'N/A'}`;

        // Select category icon
        switch (finding.category.toLowerCase()) {
            case 'secret':
                this.iconPath = new vscode.ThemeIcon('key');
                break;
            case 'sast':
                this.iconPath = new vscode.ThemeIcon('bug');
                break;
            case 'sca':
                this.iconPath = new vscode.ThemeIcon('package');
                break;
            case 'resilience':
                this.iconPath = new vscode.ThemeIcon('shield');
                break;
            case 'iac':
                this.iconPath = new vscode.ThemeIcon('server');
                break;
            default:
                this.iconPath = new vscode.ThemeIcon('alert');
        }

        const absPath = path.isAbsolute(finding.file)
            ? finding.file
            : path.join(this.workspaceRoot, finding.file);

        this.command = {
            command: 'vscode.open',
            title: 'Open File',
            arguments: [
                vscode.Uri.file(absPath),
                {
                    selection: new vscode.Range(
                        Math.max(0, finding.line_start - 1),
                        0,
                        Math.max(0, finding.line_start - 1),
                        100
                    )
                }
            ]
        };
    }
}

export class EmptyStateItem extends TreeItem {
    constructor() {
        super('No security findings identified', vscode.TreeItemCollapsibleState.None);
        this.iconPath = new vscode.ThemeIcon('check');
        this.description = 'Clean';
    }
}
