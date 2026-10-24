<?php
// Test fixture for PHP security rules

function test_php($conn, $pdo, $input) {
    // ruleid: org-php-sql-injection
    $conn->query("SELECT * FROM users WHERE id = " . $input);

    // ruleid: org-php-command-injection
    exec($input);

    // ruleid: org-php-unsafe-deserialization
    unserialize($input);

    // ruleid: org-php-weak-crypto-md5
    md5($input);
}

function ok_php($pdo, $input) {
    // ok: org-php-sql-injection
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
    $stmt->execute(['id' => $input]);

    // ok: org-php-weak-crypto-md5
    password_hash($input, PASSWORD_BCRYPT);
}
