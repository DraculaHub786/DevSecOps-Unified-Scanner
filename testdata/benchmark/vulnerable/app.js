const child_process = require('child_process');

// TP 1: Secret
const AWS_KEY = "AKIA1111222233334444";

// TP 2: Command Injection
function runCmd(req, res) {
    const cmd = req.query.cmd;
    child_process.exec(cmd, (err, stdout) => {
        res.send(stdout);
    });
}

// TP 3: SQL Injection
function queryDb(req, res, db) {
    const q = "SELECT * FROM users WHERE id = '" + req.params.id + "'";
    db.query(q);
}
