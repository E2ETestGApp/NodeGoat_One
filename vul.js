// Intentionally vulnerable file for SAST testing.
// DO NOT USE IN PRODUCTION.

const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ❌ Hardcoded secret / credential
const JWT_SECRET = "SECRET123-hardcoded-secret-please-rotate";

// ❌ Insecure hash (MD5) usage
function weakHash(input) {
  return crypto.createHash('md5').update(input).digest('hex');
}

// ❌ SQL Injection (string concatenation)
// (No DB required for SAST; pattern alone is usually flagged)
app.get('/user', (req, res) => {
  const name = req.query.name || 'guest';
  const sql = "SELECT * FROM users WHERE name = '" + name + "'"; // Vulnerable
  // pretend to run query...
  res.send({ sqlPreview: sql });
});

// ❌ Command Injection via child_process.exec
app.get('/exec', (req, res) => {
  const cmd = typeof req.query.cmd === 'string' && req.query.cmd.trim() !== '' ? req.query.cmd.trim() : 'echo hello';
  const allowedCommands = {
    'echo hello': { file: 'echo', args: ['hello'] },
    'echo goodbye': { file: 'echo', args: ['goodbye'] },
    date: { file: 'date', args: [] }
  };
  const selected = allowedCommands[cmd];

  if (!selected) {
    return res.status(400).send('Invalid command');
  }

  const { execFile } = require('child_process');
  execFile(selected.file, selected.args, (err, stdout, stderr) => {
    if (err) return res.status(500).send(String(err));
    res.send({ stdout, stderr });
  });
});

// ❌ Path Traversal (unsanitized file path)
app.get('/read', (req, res) => {
  const file = req.query.file || 'vulnerable.js';
  // join but still vulnerable due to unvalidated input and use of .. segments
  const p = path.join(__dirname, file);
  fs.readFile(p, 'utf8', (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.type('text/plain').send(data);
  });
});

// ❌ Reflected XSS (unsanitized output)
app.get('/hello', (req, res) => {
  const name = req.query.name || 'world';
  res.send(`<h1>Hello ${name}</h1>`); // Vulnerable to XSS e.g., ?name=<img src=x onerror=alert(1)>
});

// ❌ Open Redirect (unvalidated redirect target)
app.get('/go', (req, res) => {
  const next = req.query.next || 'https://example.com';
  res.redirect(next); // Vulnerable
});

// ❌ Unsafe eval
app.get('/eval', (req, res) => {
  const expr = req.query.expr || '2+2';
  try {
    // eslint-disable-next-line no-eval
    const result = eval(expr); // Vulnerable
    res.send({ result });
  } catch (e) {
    res.status(400).send('bad expr');
  }
});

// ❌ Insecure sandboxing (VM with untrusted input)
app.post('/vm', (req, res) => {
  const code = req.body && req.body.code ? req.body.code : 'process.exit()';
  try {
    const r = vm.runInThisContext(code); // Vulnerable
    res.send({ r });
  } catch (e) {
    res.status(400).send('bad code');
  }
});

// ❌ Use of hardcoded secret + weak hash combined
app.post('/login', (req, res) => {
  const { username = 'user', password = 'pass' } = req.body || {};
  const hashed = weakHash(password); // MD5
  // pretend JWT signing with hardcoded secret
  const fakeJwt = Buffer.from(`${username}:${hashed}:${JWT_SECRET}`).toString('base64');
  res.send({ token: fakeJwt });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Vulnerable app on :${PORT}`));
``