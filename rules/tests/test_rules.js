const fs = require('fs');
const path = require('path');
const child_process = require('child_process');
const crypto = require('crypto');
const axios = require('axios');
const cors = require('cors');

function testJS(req, res, db, input) {
  // ruleid: org-js-sql-injection-concat
  db.query("SELECT * FROM users WHERE id = " + input);

  // ruleid: org-js-command-injection-exec
  child_process.exec(input);

  // ruleid: org-js-code-injection-eval
  eval(input);

  // ruleid: org-js-reject-unauthorized-false
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

  // ruleid: org-js-weak-crypto-md5-sha1
  crypto.createHash('md5');

  // ruleid: org-js-insecure-math-random
  Math.random();

  // ruleid: org-js-path-traversal-fs
  fs.readFile(path.join('/base', req.query.file));

  // ruleid: org-js-open-redirect
  res.redirect(req.query.url);

  // ruleid: org-js-cors-wildcard-with-credentials
  cors({
    origin: "*",
    credentials: true
  });

  // ruleid: org-js-ssrf-axios-fetch
  axios.get(req.query.url);

  // ruleid: org-js-cookie-missing-httponly-secure
  res.cookie('session', 'val', { httpOnly: false });

  // ruleid: org-js-raw-innerhtml-xss
  document.getElementById('app').innerHTML = input;
}
