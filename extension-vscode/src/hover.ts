import type * as vscodeTypes from 'vscode';
import { Finding } from './ipc/client';

export const ALLOWED_HOVER_COMMANDS = [
    'sentinel.showFindingDetails',
    'sentinel.applyFix'
] as const;

let vscodeModule: typeof vscodeTypes | undefined;
try {
    vscodeModule = require('vscode');
} catch {
    // vscode is provided by the VS Code host at runtime; safely absent in standalone test runners
}

/**
 * Escapes Markdown formatting characters to prevent injection.
 */
export function escapeMarkdown(text: string): string {
    if (!text) return '';
    return text.replace(/[\\`*_\[\]()#+\-.!<>]/g, '\\$&');
}

/**
 * Neutralizes potential executable URI schemes (command:, javascript:, data:) from untrusted finding data.
 */
export function sanitizeUntrustedText(text: string): string {
    if (!text) return '';
    return text.replace(/\b(command|javascript|data|vbscript):/gi, '$1_disarmed:');
}

/**
 * Builds a secure vscode.MarkdownString hover for a finding.
 * Enforces:
 * 1. md.supportHtml = false (no HTML injection)
 * 2. md.isTrusted restricted strictly to allowedCommands whitelist (no arbitrary command execution)
 * 3. Untrusted finding attributes (message, snippet, rule, description) sanitized and added as plain text.
 */
export function buildFindingHover(finding: Finding): any {
    const vscode = vscodeModule || require('vscode');
    const md = new vscode.MarkdownString('', true);
    md.supportHtml = false;
    md.isTrusted = {
        enabledCommands: [...ALLOWED_HOVER_COMMANDS]
    };

    md.appendMarkdown(`### 🛡️ Sentinel: `);
    md.appendText(finding.rule);
    md.appendMarkdown(`\n\n`);

    const engineLabel = finding.engine === 'embedded'
        ? '⚡ Embedded Lite Engine'
        : '🔬 External Tool (Production)';
    md.appendMarkdown(`**Engine:** \`${engineLabel}\`\n\n`);
    md.appendMarkdown(`**Severity:** \`${finding.severity.toUpperCase()}\` | **Category:** \`${finding.category}\` | **Risk Score:** \`${finding.risk_score}/100\`\n\n`);

    // Untrusted message appended as plain text
    md.appendText(sanitizeUntrustedText(finding.message));
    md.appendMarkdown(`\n\n`);

    if (finding.cwe) {
        const cweDigits = finding.cwe.replace(/^CWE-/, '');
        const safeCweId = encodeURIComponent(cweDigits);
        md.appendMarkdown(`[View ${escapeMarkdown(finding.cwe)} Advisory](https://cwe.mitre.org/data/definitions/${safeCweId}.html)\n\n`);
    }

    if (finding.fix_suggestion) {
        md.appendMarkdown(`💡 **Quick Fix:** `);
        md.appendText(sanitizeUntrustedText(finding.fix_suggestion.description));
        md.appendMarkdown(`\n\n`);
    }

    const explainUri = `command:sentinel.showFindingDetails?${encodeURIComponent(JSON.stringify(finding.id))}`;
    md.appendMarkdown(`[Explain Finding](${explainUri})`);

    if (finding.fix_suggestion) {
        const fixUri = `command:sentinel.applyFix?${encodeURIComponent(JSON.stringify(finding.id))}`;
        md.appendMarkdown(` | [Apply Quick Fix](${fixUri})`);
    }

    return md;
}

/**
 * Pure function to format hover preview and command whitelist for testing without vscode runtime.
 */
export function formatFindingHoverSummary(finding: Finding): {
    header: string;
    sanitizedMessage: string;
    sanitizedRule: string;
    allowedCommands: readonly string[];
} {
    return {
        header: `### 🛡️ Sentinel: ${escapeMarkdown(finding.rule)}`,
        sanitizedMessage: sanitizeUntrustedText(finding.message),
        sanitizedRule: sanitizeUntrustedText(finding.rule),
        allowedCommands: ALLOWED_HOVER_COMMANDS
    };
}
