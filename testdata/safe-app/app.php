<?php
// Safe PHP application file

function getUser($pdo, $id) {
    $stmt = $pdo->prepare('SELECT id, name, email FROM users WHERE id = :id');
    $stmt->execute(['id' => intval($id)]);
    return $stmt->fetch();
}

function hashPassword($plain) {
    return password_hash($plain, PASSWORD_BCRYPT);
}
