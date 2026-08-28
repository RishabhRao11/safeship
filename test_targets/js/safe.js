// Safe fixture: the correct version of every pattern in vulnerable.js.
// Zero findings expected from rules/vibe_patterns_js.yaml.
//
// This file is the more important of the pair. A rule that fires here is a false
// positive shipped to a non-technical user, which is the failure mode the whole
// project is built to avoid.
const express = require('express');
const mysql = require('mysql2');
const { execFile } = require('child_process');
const cors = require('cors');

const app = express();
const db = mysql.createConnection({ host: 'localhost' });

// RULE 3 -- read from the environment. This is the fix, and must not be flagged.
const API_KEY = process.env.API_KEY;
const config = { stripeSecret: process.env.STRIPE_SECRET };

// RULE 4 -- publishable keys are designed to ship in client code.
const stripePublishable = "pk_live_51QpR7mNvXk2LaBcD9fHjT4wY";

// RULE 7 -- explicit origin list.
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));

// RULE 1 -- parameterised query. The placeholder is the whole point.
app.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id], (e, rows) => res.json(rows));
});

// RULE 1 -- a constant query with no interpolation is not injectable.
app.get('/all', (req, res) => {
  const q = "SELECT id, name FROM products";
  db.query(q, (e, rows) => res.json(rows));
});

// RULE 1 -- a template literal that is not SQL. JS uses backticks everywhere.
app.get('/greet', (req, res) => {
  const message = `Hello ${req.query.name}, welcome back`;
  res.json({ message });
});

// RULE 2 -- parse the value instead of executing it.
app.get('/calc', (req, res) => {
  res.json(JSON.parse(req.query.payload));
});

// RULE 2 -- eval on a literal the developer chose is pointless, not dangerous.
const answer = eval("2 + 2");

// RULE 6 -- argument array, no shell involved, nothing to inject into.
app.get('/ping', (req, res) => {
  execFile('ping', ['-c', '1', req.query.host], (e, out) => res.send(out));
});

// RULE 6 -- a fully hardcoded command has no injection point.
execFile('/bin/ls', ['-la'], () => {});

// RULE 5 -- a route that reads config without dumping the environment.
app.get('/health', (req, res) => {
  res.json({ ok: true, version: process.env.APP_VERSION });
});

app.listen(3000);
