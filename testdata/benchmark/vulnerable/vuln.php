<?php
// TP: SQL injection via concatenation (CWE-89)
function getUser($conn, $id) {
    $result = $conn->query("SELECT * FROM users WHERE id = " . $id);
    return $result->fetch_assoc();
}

// TP: command injection (CWE-78)
function pingHost($host) {
    return shell_exec($host);
}

// TP: insecure deserialization (CWE-502)
function loadState($blob) {
    return unserialize($blob);
}

// TP: weak cryptography (CWE-327)
function fingerprint($value) {
    return md5($value);
}

// Negative: PDO prepared statement
function getUserSafe($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}
