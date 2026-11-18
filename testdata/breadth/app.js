const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

// SQL injection via concat
app.get('/u', (req, res) => {
  const q = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
  db.query(q, (e, r) => res.send(r));
});

// Command injection
app.get('/ping', (req, res) => {
  require('child_process').exec('ping ' + req.query.host, (e, o) => res.send(o));
});

// Hardcoded JWT secret
const token = jwt.sign({ sub: 1 }, "my-super-secret-jwt-key-12345");

// Insecure TLS
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
