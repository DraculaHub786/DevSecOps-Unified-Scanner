import * as vscode from 'vscode';
import * as path from 'path';
import { Finding } from '../ipc/client';

export type GroupingMode = 'severity' | 'file' | 'category';

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<TreeItem | undefined | null | void> = new vscode.EventEmitter<TreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<TreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private findings: Finding[] = [];
    private workspaceRoot: string = '';
    private groupingMode: GroupingMode = 'severity';
    private coverageInfo: any = null;

    public refresh(findings: Finding[], workspaceRoot: string, coverageInfo?: any): void {
        this.findings = findings;
        this.workspaceRoot = workspaceRoot;
        if (coverageInfo) {
            this.coverageInfo = coverageInfo;
        }
        this._onDidChangeTreeData.fire();
    }

    public toggleGrouping(): GroupingMode {
        if (this.groupingMode === 'severity') {
            this.groupingMode = 'category';
        } else if (this.groupingMode === 'category') {
            this.groupingMode = 'file';
        } else {
            this.groupingMode = 'severity';
        }
        this._onDidChangeTreeData.fire();
        return this.groupingMode;
    }

    public getGroupingMode(): GroupingMode {
        return this.groupingMode;
    }

    getTreeItem(element: TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: TreeItem): Thenable<TreeItem[]> {
        if (!element) {
            const rootItems: TreeItem[] = [];

            // Add Coverage node at the top
            rootItems.push(new CoverageItem(this.coverageInfo));

            if (this.findings.length === 0) {
                rootItems.push(new EmptyStateItem());
                return Promise.resolve(rootItems);
            }

            if (this.groupingMode === 'severity') {
                const groups = ['critical', 'high', 'medium', 'low'];
                for (const sev of groups) {
                    const count = this.findings.filter(f => f.severity.toLowerCase() === sev).length;
                    if (count > 0) {
                        let label = `${sev.toUpperCase()} (${count})`;
                        let icon = 'error';
                        if (sev === 'critical') icon = 'flame';
                        if (sev === 'medium') icon = 'warning';
                        if (sev === 'low') icon = 'info';

                        rootItems.push(new GroupItem(label, 'severity', sev, count, icon));
                    }
                }
            } else if (this.groupingMode === 'category') {
                const categories = ['sast', 'sca', 'secret', 'iac', 'resilience', 'dast'];
                for (const cat of categories) {
                    const count = this.findings.filter(f => f.category.toLowerCase() === cat).length;
                    if (count > 0) {
                        let icon = 'alert';
                        if (cat === 'secret') icon = 'key';
                        else if (cat === 'sast') icon = 'bug';
                        else if (cat === 'sca') icon = 'package';
                        else if (cat === 'iac') icon = 'server';
                        else if (cat === 'resilience') icon = 'shield';
                        else if (cat === 'dast') icon = 'globe';

                        rootItems.push(new GroupItem(cat.toUpperCase(), 'category', cat, count, icon));
                    }
                }
            } else if (this.groupingMode === 'file') {
                const fileMap = new Map<string, number>();
                for (const f of this.findings) {
                    const rel = path.relative(this.workspaceRoot, path.isAbsolute(f.file) ? f.file : path.join(this.workspaceRoot, f.file)).replace(/\\/g, '/');
                    fileMap.set(rel, (fileMap.get(rel) || 0) + 1);
                }
                for (const [file, count] of fileMap.entries()) {
                    rootItems.push(new GroupItem(file, 'file', file, count, 'file-code'));
                }
            }

            return Promise.resolve(rootItems);
        }

        if (element instanceof GroupItem) {
            let matches: Finding[] = [];
            if (element.kind === 'severity') {
                matches = this.findings.filter(f => f.severity.toLowerCase() === element.key);
            } else if (element.kind === 'category') {
                matches = this.findings.filter(f => f.category.toLowerCase() === element.key);
            } else if (element.kind === 'file') {
                matches = this.findings.filter(f => {
                    const rel = path.relative(this.workspaceRoot, path.isAbsolute(f.file) ? f.file : path.join(this.workspaceRoot, f.file)).replace(/\\/g, '/');
                    return rel === element.key;
                });
            }

            const items = matches.map(f => new FindingItem(f, this.workspaceRoot));
            return Promise.resolve(items);
        }

        return Promise.resolve([]);
    }
}

export abstract class TreeItem extends vscode.TreeItem {}

export class GroupItem extends TreeItem {
    constructor(
        public readonly label: string,
        public readonly kind: 'severity' | 'category' | 'file',
        public readonly key: string,
        public readonly count: number,
        icon: string
    ) {
        super(`${label} (${count})`, vscode.TreeItemCollapsibleState.Expanded);
        this.iconPath = new vscode.ThemeIcon(icon);
    }
}

export class CoverageItem extends TreeItem {
    constructor(coverageInfo: any) {
        let label = 'Coverage: 6/6 Categories Active';
        let detail = 'SAST, SCA, Secrets, IaC, Resilience, DAST';
        let icon = 'shield-check';

        if (coverageInfo) {
            const active = coverageInfo.activeCategories ?? 6;
            const total = coverageInfo.totalCategories ?? 6;
            label = `Coverage: ${active}/${total} Categories Active`;
            if (active < total) {
                icon = 'shield';
                detail = 'Some categories skipped or operating in lite mode';
            }
        }

        super(label, vscode.TreeItemCollapsibleState.None);
        this.description = detail;
        this.iconPath = new vscode.ThemeIcon(icon);
        this.tooltip = `Sentinel Unified DevSecOps Coverage\n${detail}`;
    }
}

export class FindingItem extends TreeItem {
    constructor(public readonly finding: Finding, private workspaceRoot: string) {
        super(`${finding.rule}: ${path.basename(finding.file)}:${finding.line_start}`, vscode.TreeItemCollapsibleState.None);

        this.contextValue = 'findingItem';
        this.description = `[${finding.severity.toUpperCase()}] Risk: ${finding.risk_score}`;
        this.tooltip = `${finding.message}\nCWE: ${finding.cwe || 'N/A'}\nFile: ${finding.file}:${finding.line_start}`;

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
            case 'dast':
                this.iconPath = new vscode.ThemeIcon('globe');
                break;
            default:
                this.iconPath = new vscode.ThemeIcon('alert');
        }

        const absPath = path.isAbsolute(finding.file)
            ? finding.file
            : path.join(this.workspaceRoot, finding.file);

        this.command = {
            command: 'sentinel.showFindingDetails',
            title: 'Explain Finding',
            arguments: [finding.id]
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
