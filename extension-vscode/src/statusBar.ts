import * as vscode from 'vscode';
import { Finding } from './ipc/client';

export class SentinelStatusBar {
    private item: vscode.StatusBarItem;

    constructor() {
        this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
        this.item.command = 'sentinel.scanWorkspace';
        this.setIdle();
        this.item.show();
    }

    public setScanning(): void {
        this.item.text = '$(sync~spin) Sentinel: Scanning...';
        this.item.tooltip = 'Sentinel scan currently in progress';
    }

    public setResults(findings: Finding[], mode: string = 'full'): void {
        const crit = findings.filter(f => f.severity.toLowerCase() === 'critical').length;
        const high = findings.filter(f => f.severity.toLowerCase() === 'high').length;
        const med = findings.filter(f => f.severity.toLowerCase() === 'medium').length;
        const modeLabel = mode.toLowerCase() === 'lite' ? '[Lite]' : '[Full]';

        if (crit + high + med === 0) {
            this.item.text = `$(shield) Sentinel ${modeLabel}: Clean`;
            this.item.tooltip = `Sentinel DevSecOps (${mode.toUpperCase()} Mode): 0 critical or high findings`;
        } else {
            this.item.text = `$(shield) Sentinel ${modeLabel}: ${crit} 🚨 ${high} ⚠️`;
            this.item.tooltip = `Sentinel (${mode.toUpperCase()} Mode) Findings: ${crit} Critical, ${high} High, ${med} Medium. Click to re-scan.`;
        }
    }

    public setIdle(): void {
        this.item.text = '$(shield) Sentinel: Ready';
        this.item.tooltip = 'Click to scan workspace';
    }

    public dispose(): void {
        this.item.dispose();
    }
}
