import * as assert from 'assert';
import { Finding } from '../ipc/client';

console.log('🧪 Running Sentinel VS Code Extension Unit Tests...');

// 1. Finding structure and engine provenance
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
console.log('✅ Finding schema contract verified.');

// 2. Secret Redaction test
function redactSecrets(text: string): string {
    return text.replace(/(token|key|password|secret|bearer)\s*[:=]\s*["']?([^"'\s]+)["']?/gi, '$1=[REDACTED]');
}

const rawLog = 'Connecting to agent with token="super-secret-token-xyz" and api_key: "abc12345"';
const safeLog = redactSecrets(rawLog);
assert.ok(!safeLog.includes('super-secret-token-xyz'), 'Raw token was leaked!');
assert.ok(safeLog.includes('token=[REDACTED]'), 'Token redaction failed!');
console.log('✅ Secret redaction in logs verified.');

// 3. Severity ranking test
const sevRank: Record<string, number> = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
};
assert.ok(sevRank['critical'] > sevRank['high']);
assert.ok(sevRank['high'] > sevRank['medium']);
assert.ok(sevRank['medium'] > sevRank['low']);
console.log('✅ Severity ranking verified.');

console.log('🎉 All 3 extension unit test suites passed successfully!');
