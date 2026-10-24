const path = require('path');

function safeQuery(db, id) {
    db.query("SELECT * FROM users WHERE id = ?", [parseInt(id, 10)]);
}

module.exports = { safeQuery };
