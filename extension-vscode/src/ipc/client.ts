import * as net from 'net';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface Finding {
    id: string;
    source: string;
    engine?: string;
    category: string;
    rule: string;
    severity: string;
    cwe?: string;
    cve?: string;
    cvss?: number;
    file: string;
    line_start: number;
    line_end: number;
    message: string;
    reachable?: boolean;
    risk_score: number;
    fix_suggestion?: {
        kind: string;
        description: string;
        diff?: string;
        confidence: string;
    };
}

export class AgentClient {
    constructor(private host: string = '127.0.0.1', private port: number = 48921) {}

    private getSessionToken(): string {
        const cacheDir = process.platform === 'win32'
            ? process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local')
            : process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache');

        const tokenPath = path.join(cacheDir, 'sentinel', 'agent.token');
        try {
            if (fs.existsSync(tokenPath)) {
                return fs.readFileSync(tokenPath, 'utf8').trim();
            }
        } catch {
            // ignore
        }
        return '';
    }

    private sendRequest<T>(method: string, params: any): Promise<T> {
        return new Promise((resolve, reject) => {
            const socket = new net.Socket();
            let responseData = '';

            socket.setTimeout(8000);

            socket.connect(this.port, this.host, () => {
                const req = {
                    jsonrpc: '2.0',
                    id: Date.now(),
                    token: this.getSessionToken(),
                    method,
                    params
                };
                socket.write(JSON.stringify(req) + '\n');
            });

            socket.on('data', (chunk) => {
                responseData += chunk.toString();
                if (responseData.includes('\n')) {
                    socket.end();
                }
            });

            socket.on('end', () => {
                try {
                    const parsed = JSON.parse(responseData.trim());
                    if (parsed.error) {
                        reject(new Error(parsed.error.message || 'Agent error'));
                    } else {
                        resolve(parsed.result as T);
                    }
                } catch (e) {
                    reject(e);
                }
            });

            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error('Agent request timed out'));
            });

            socket.on('error', (err) => {
                reject(err);
            });
        });
    }

    async scanRun(repoPath: string, paths: string[] = [], incremental: boolean = false, offline: boolean = false, policyPath?: string): Promise<string> {
        const res = await this.sendRequest<{ scanId: string }>('scan.run', {
            repoPath,
            paths,
            incremental,
            offline,
            policyPath
        });
        return res.scanId;
    }

    async scanStatus(scanId: string): Promise<{ state: string; progress: number }> {
        return this.sendRequest<{ state: string; progress: number }>('scan.status', { scanId });
    }

    async getFindings(scanId: string, file?: string): Promise<Finding[]> {
        return this.sendRequest<Finding[]>('findings.list', { scanId, file });
    }

    async previewFix(repoPath: string, findingId: string): Promise<{ diff: string; description: string }> {
        return this.sendRequest<{ diff: string; description: string }>('fix.preview', { repoPath, findingId });
    }

    async applyFix(repoPath: string, findingId: string): Promise<{ success: boolean; appliedDiff: string }> {
        return this.sendRequest<{ success: boolean; appliedDiff: string }>('fix.apply', { repoPath, findingId });
    }

    async handshake(clientVersion: string = '1.0.0'): Promise<{ status: string; serverVersion: string; capabilities: string[]; protocolVersion: string }> {
        return this.sendRequest<{ status: string; serverVersion: string; capabilities: string[]; protocolVersion: string }>('agent.handshake', { client: 'vscode', version: clientVersion });
    }

    async ping(): Promise<{ status: string; version: string }> {
        return this.sendRequest<{ status: string; version: string }>('agent.ping', {});
    }

    async getCoverage(): Promise<any> {
        return this.sendRequest<any>('agent.coverage', {});
    }

    async runDoctor(): Promise<any[]> {
        return this.sendRequest<any[]>('doctor.run', {});
    }

    async createBaseline(repoPath: string): Promise<{ success: boolean; count: number; path: string }> {
        return this.sendRequest<{ success: boolean; count: number; path: string }>('baseline.create', { repoPath });
    }

    async addSuppression(repoPath: string, findingId: string, reason: string, expires?: string): Promise<{ success: boolean; findingId: string; file: string }> {
        return this.sendRequest<{ success: boolean; findingId: string; file: string }>('suppress.add', { repoPath, findingId, reason, expires });
    }

    async runThreatModel(repoPath: string): Promise<any> {
        return this.sendRequest<any>('threatmodel.run', { repoPath });
    }

    async generateSBOM(repoPath: string, format: string = 'cyclonedx', out: string = ''): Promise<any> {
        return this.sendRequest<any>('sbom.generate', { repoPath, format, out });
    }

    async runDAST(target: string, authorized: boolean, allowPrivate: boolean = false): Promise<Finding[]> {
        return this.sendRequest<Finding[]>('dast.run', { target, authorized, allowPrivate });
    }
}
