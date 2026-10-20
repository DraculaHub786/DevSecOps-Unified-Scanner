const express = require('express');
const child_process = require('child_process');
const app = express();

// Hardcoded secret (Gitleaks / Secret category)
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const AWS_SECRET = "AKIAIOSFODNN7EXAMPLE";

// SAST: Command injection
app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    child_process.exec(cmd, (err, stdout) => {
        res.send(stdout);
    });
});

// SAST: SQL Injection via concatenation
app.get('/user/:id', (req, res) => {
    const query = "SELECT * FROM users WHERE id = '" + req.params.id + "'";
    db.query(query, (err, rows) => {
        res.json(rows);
    });
});

app.listen(3000, () => {
    console.log("Server listening on port 3000");
});
