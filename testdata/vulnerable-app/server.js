const express = require('express');
const child_process = require('child_process');
const app = express();

// Intentionally fake secrets: random but well-formed so real detectors flag them
const GITHUB_TOKEN = "ghp_R8kD3mZq1Xv7LpN2sT9wYb4HcF6jGa0UeQ5o";
const AWS_ACCESS_KEY_ID = "AKIAZ3MSJV4WWDNTQHPW";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-456789abcdefghijklmnopqrst";
const SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";

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
