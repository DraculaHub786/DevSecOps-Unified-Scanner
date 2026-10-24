# Sentinel Security Rules Catalog

Sentinel embeds a comprehensive rule catalog covering **SAST (Go, JavaScript, Python, Java)**, **CI/CD & GitHub Actions**, **Software Supply Chain**, and **API Resilience & DoS**.

Every rule includes full security metadata: **CWE**, **OWASP 2021 Category**, **Default Severity**, **Confidence**, and **Actionable Remediation Guidance**.

---

## Summary Matrix

| Category | Rules Count | Supported Languages / Targets |
|---|---|---|
| **SAST (Application Security)** | 68 | Go, JavaScript / TypeScript, Python, Java, PHP, C#, Ruby |
| **CI/CD & GitHub Actions** | 4 | `.github/workflows/*.{yml,yaml}` |
| **Software Supply Chain** | 4 | Dockerfile, package.json |
| **API Resilience & DoS** | 2 | Go, JavaScript, Python |
| **Total Rules** | **78** | All 78 verified via `sentinel rules test` |

### Supported Language Coverage Matrix

Every supported language ships with built-in coverage for the core OWASP Top 10 vulnerability classes:

| Language | SQLi | Command Injection | Deserialization | Weak Crypto | Secrets | Path Traversal | SSRF | XSS |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Go** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **JavaScript / TypeScript** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Python** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Java** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **PHP** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **C# (.NET)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Ruby** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Additional Registry Rule Packs

Users can opt into additional vendor and community Semgrep rule packs in `.sentinel.yml`:

```yaml
scanners:
  sast:
    enabled: true
    packs:
      - p/php
      - p/csharp
      - p/ruby
```

---

## 1. CI/CD & GitHub Actions Security Rules

### `org-gha-dangerous-pull-request-target`
- **Severity**: HIGH | **CWE**: CWE-284 | **OWASP**: A01:2021-Broken Access Control | **Confidence**: HIGH
- **Description**: Triggering workflow runs on `pull_request_target` grants repository read/write tokens and access to secrets to potentially untrusted forks.
- **Remediation**: Use `pull_request` instead unless explicitly necessary. If `pull_request_target` is required, never checkout untrusted pull request HEAD code before running sensitive build or deploy steps.

### `org-gha-unpinned-action`
- **Severity**: MEDIUM | **CWE**: CWE-1357 | **OWASP**: A08:2021-Software and Data Integrity Failures | **Confidence**: HIGH
- **Description**: Action step references a mutable branch or floating tag (e.g. `@main`, `@master`, `@latest`) instead of an immutable 40-character commit SHA.
- **Remediation**: Pin actions to full commit SHAs with inline version comments: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`.

### `org-gha-write-all-permissions`
- **Severity**: HIGH | **CWE**: CWE-250 | **OWASP**: A01:2021-Broken Access Control | **Confidence**: HIGH
- **Description**: Workflow or job grants `permissions: write-all`, violating the principle of least privilege.
- **Remediation**: Define explicit granular permissions (e.g. `contents: read`, `pull-requests: write`, `security-events: write`).

### `org-gha-untrusted-event-injection`
- **Severity**: CRITICAL | **CWE**: CWE-78 | **OWASP**: A03:2021-Injection | **Confidence**: HIGH
- **Description**: Direct inline shell execution interpolating untrusted GitHub context expressions (`${{ github.event.issue.title }}`, `head_ref`, etc.) allows arbitrary script injection.
- **Remediation**: Pass context data into step environment variables (`env: TITLE: ${{ github.event.issue.title }}`) and reference the environment variable (`$TITLE` / `"$TITLE"`) in the shell script.

---

## 2. Software Supply Chain Rules

### `org-supplychain-docker-latest-tag`
- **Severity**: WARNING | **CWE**: CWE-1188 | **OWASP**: A05:2021-Security Misconfiguration | **Confidence**: HIGH
- **Description**: Container image base uses mutable `:latest` or untagged reference in Dockerfile.
- **Remediation**: Pin to an immutable semver release tag or cryptographic image digest (e.g. `FROM alpine:3.20.3@sha256:...`).

### `org-supplychain-curl-pipe-sh`
- **Severity**: ERROR | **CWE**: CWE-494 | **OWASP**: A08:2021-Software and Data Integrity Failures | **Confidence**: HIGH
- **Description**: Downloading external scripts and directly piping into `sh` or `bash` (`curl | sh` / `wget | bash`) bypasses integrity checks and permits supply chain takeover.
- **Remediation**: Download the script to a file, verify its cryptographic SHA-256 checksum against an official pinned signature, and then execute.

### `org-supplychain-npm-lifecycle-script`
- **Severity**: WARNING | **CWE**: CWE-829 | **OWASP**: A08:2021-Software and Data Integrity Failures | **Confidence**: HIGH
- **Description**: Risky package lifecycle scripts (`preinstall`, `postinstall`) execute arbitrary code automatically on `npm install`.
- **Remediation**: Avoid executing uncontrolled code during installation, or run `npm install --ignore-scripts` in CI.

### `org-supplychain-npm-wildcard-dependency`
- **Severity**: WARNING | **CWE**: CWE-1357 | **OWASP**: A08:2021-Software and Data Integrity Failures | **Confidence**: HIGH
- **Description**: Package dependency version declared with wildcards (`*`, `x`, `latest`), exposing builds to breaking changes and compromised package versions.
- **Remediation**: Pin exact semantic versions or bounded caret ranges and commit a lockfile (`package-lock.json`).

---

## 3. Application Security (SAST) Rules

### Injection (SQL, Command, Code, LDAP)
* **`org-go-sql-injection-sprintf`** (ERROR / CWE-89): Formatted SQL query construction in Go. Use parameterized queries `db.Query(query, args...)`.
* **`org-go-sql-injection-concat`** (ERROR / CWE-89): String concatenation in SQL query in Go.
* **`org-js-sql-injection-concat`** (ERROR / CWE-89): Concatenating user inputs into database queries in JavaScript / Node.js.
* **`org-python-sql-injection-format`** (ERROR / CWE-89): Formatted string SQL queries in Python. Use DB-API parameterized queries.
* **`org-java-sql-injection-concat`** (ERROR / CWE-89): Concatenation in JDBC statements in Java. Use `PreparedStatement`.
* **`org-go-command-injection-sh`** (ERROR / CWE-78): Passing unsanitized input to `exec.Command("sh", "-c", ...)`.
* **`org-js-command-injection-exec`** (ERROR / CWE-78): Unsanitized arguments passed to `child_process.exec()`.
* **`org-js-code-injection-eval`** (ERROR / CWE-94): Dynamic evaluation of strings using `eval()`.
* **`org-python-command-injection-shell`** (ERROR / CWE-78): Invoking `subprocess.Popen(..., shell=True)`.
* **`org-python-code-injection-eval`** (ERROR / CWE-94): Evaluation with `eval()` or `exec()`.
* **`org-java-command-injection-runtime`** (ERROR / CWE-78): Calling `Runtime.getRuntime().exec(cmd)`.
* **`org-java-ldap-injection`** (ERROR / CWE-90): Unsanitized filter expressions in Java JNDI/LDAP searches.

### Broken Access Control & Path Traversal
* **`org-go-path-traversal-open`** (ERROR / CWE-22): Opening file paths using user-controlled parameters in Go without `filepath.Clean` and boundary validation.
* **`org-js-path-traversal-fs`** (ERROR / CWE-22): Accessing filesystem paths via `fs.readFile` with dynamic parameters.
* **`org-python-path-traversal-open`** (ERROR / CWE-22): Using `open()` on untrusted path components in Python.
* **`org-java-path-traversal-file`** (ERROR / CWE-22): Constructing `new File(base, untrustedPath)` without verifying canonical path boundaries.
* **`org-go-open-redirect`** (ERROR / CWE-601): HTTP redirecting to untrusted dynamic URLs in Go.
* **`org-js-open-redirect`** (ERROR / CWE-601): Redirecting client via `res.redirect(untrustedUrl)` in Express.js.
* **`org-python-open-redirect`** (ERROR / CWE-601): Unvalidated URL redirects in Django/Flask (`redirect(request.GET['next'])`).
* **`org-java-open-redirect`** (ERROR / CWE-601): Redirecting with `response.sendRedirect(url)` without allowlist validation.

### Cryptographic & Authentication Failures
* **`org-hardcoded-aws-credentials`** (ERROR / CWE-798): Hardcoded AWS Access Key ID (`AKIA...`).
* **`org-hardcoded-github-token`** (ERROR / CWE-798): Hardcoded GitHub personal access token (`ghp_...`).
* **`org-hardcoded-jwt-secret`** (ERROR / CWE-798): Hardcoded secret key passed into JWT signing methods.
* **`org-hardcoded-slack-webhook`** (ERROR / CWE-798): Hardcoded Slack incoming webhook URL.
* **`org-java-hardcoded-crypto-key`** (ERROR / CWE-798): Hardcoded byte arrays in `SecretKeySpec`.
* **`org-go-weak-crypto-md5-sha1`** (WARNING / CWE-328): Using MD5 or SHA1 for password hashing or cryptographic signatures in Go. Use SHA-256 or Argon2id/bcrypt.
* **`org-python-weak-crypto-md5-sha1`** (WARNING / CWE-328): Calling `hashlib.md5()` or `hashlib.sha1()`.
* **`org-js-weak-crypto-md5-sha1`** (WARNING / CWE-328): Creating MD5 or SHA1 hashes with `crypto.createHash()`.
* **`org-go-weak-des-cipher`** (ERROR / CWE-327): Using insecure legacy DES cipher `des.NewCipher`. Use AES-GCM or ChaCha20-Poly1305.
* **`org-jwt-none-algorithm`** (ERROR / CWE-327): Explicitly permitting `"none"` algorithm in JWT verification (Go, JavaScript, TypeScript, Java).
* **`org-jwt-none-algorithm-python`** (ERROR / CWE-327): Insecure JWT decode configuration `algorithms=["none"]` disabling cryptographic signature verification (Python).
* **`org-go-insecure-skip-verify`** (ERROR / CWE-295): Disabling TLS certificate validation (`InsecureSkipVerify: true`) in Go.
* **`org-python-requests-verify-false`** (ERROR / CWE-295): Disabling SSL verification (`verify=False`) in Python requests.
* **`org-js-reject-unauthorized-false`** (ERROR / CWE-295): Setting `rejectUnauthorized: false` in Node.js TLS agents.

### Insecure Deserialization & XML Parsing (XXE)
* **`org-python-unsafe-pickle`** (ERROR / CWE-502): Deserializing untrusted data with `pickle.loads()`.
* **`org-python-unsafe-yaml-load`** (ERROR / CWE-502): Calling `yaml.load()` without `SafeLoader`. Use `yaml.safe_load()`.
* **`org-java-unsafe-object-input-stream`** (ERROR / CWE-502): Using `ObjectInputStream.readObject()` on untrusted input streams.
* **`org-java-jackson-unsafe-deserialization`** (ERROR / CWE-502): Enabling default typing in Jackson `ObjectMapper.enableDefaultTyping()`.
* **`org-java-xxe-document-builder`** (ERROR / CWE-611): XML DocumentBuilder configured without disabling external DTDs and entities.
* **`org-python-xxe-processing`** (ERROR / CWE-611): Parsing XML using `lxml.etree` without `resolve_entities=False`.

### Server-Side Template Injection (SSTI) & XSS
* **`org-python-ssti-jinja2`** (ERROR / CWE-1336): Rendering dynamic user string directly with Jinja2 `Template(user_input).render()`.
* **`org-java-ssti-thymeleaf`** (ERROR / CWE-1336): Dynamic Spring Thymeleaf view names derived from user parameters.
* **`org-js-ssti-ejs`** (ERROR / CWE-1336): Compiling untrusted user strings with `ejs.render(user_str)`.
* **`org-js-raw-innerhtml-xss`** (ERROR / CWE-79): Direct assignment to `element.innerHTML` without sanitization.

### Security Misconfigurations & Cookies
* **`org-js-cookie-missing-httponly-secure`** (WARNING / CWE-1004): Cookie options missing `httpOnly: true` or `secure: true`.
* **`org-go-cookie-missing-httponly-secure`** (WARNING / CWE-1004): `http.Cookie` created with `HttpOnly: false` or `Secure: false`.
* **`org-java-cookie-missing-httponly-secure`** (WARNING / CWE-1004): Servlet cookie created without `setHttpOnly(true)` or `setSecure(true)`.
* **`org-cors-wildcard-header`** (WARNING / CWE-942): `Access-Control-Allow-Origin: *` exposed alongside authenticated credentials.
* **`org-js-cors-wildcard-with-credentials`** (ERROR / CWE-942): Express `cors()` allowing wildcard origin with `credentials: true`.
* **`org-java-spring-cors-wildcard`** (WARNING / CWE-942): `@CrossOrigin(origins = "*")` configured on sensitive Spring controller endpoints.

---

## 4. API Resilience & DoS Rules

* **`org-http-server-timeouts`** (WARNING / CWE-400): Go `http.Server` declared without `ReadHeaderTimeout`, `ReadTimeout`, or `WriteTimeout`, vulnerable to Slowloris attacks.
* **`org-bounded-request-body`** (ERROR / CWE-400): Reading HTTP request bodies using `io.ReadAll(r.Body)` without wrapping in `http.MaxBytesReader` or `io.LimitReader`.
