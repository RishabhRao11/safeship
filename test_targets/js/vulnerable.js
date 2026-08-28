// Planted fixture: the JS counterpart to test_targets/vulnerable.py.
// Every block below is what an LLM actually produces when asked for the feature.
const express = require('express');
const mysql = require('mysql2');
const { exec } = require('child_process');
const fs = require('fs');
const cors = require('cors');

const app = express();
const db = mysql.createConnection({ host: 'localhost' });

// RULE 3 -- credential-looking name, hardcoded value.
const API_KEY = "correct-horse-battery-staple-9f2a";
const config = { stripeSecret: "hunter2-not-a-real-value" };

// RULE 4 -- known credential format.
const openaiKey = "sk-Qw8vN2pLxR7mZaK4tYbE1hJdT3BlbkFJ9uCsV6nGfW0oPiXr";

// RULE 7 -- CORS open to the world.
app.use(cors({ origin: "*" }));

// RULE 1 -- SQL by template interpolation. The bug --config auto misses.
app.get('/user', (req, res) => {
  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`, (e, rows) => res.json(rows));
});

// RULE 1 -- two-step form: build into a variable, execute later.
app.get('/search', (req, res) => {
  const q = "SELECT * FROM products WHERE name LIKE '%" + req.query.term + "%'";
  db.query(q, (e, rows) => res.json(rows));
});

// RULE 2 -- eval on request input.
app.get('/calc', (req, res) => {
  res.send(String(eval(req.query.expr)));
});

// RULE 2 -- new Function is eval wearing a constructor.
app.post('/render', (req, res) => {
  const tpl = new Function(req.body.template);
  res.send(tpl());
});

// RULE 6 -- shell command built from request input.
app.get('/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (e, out) => res.send(out));
});

// RULE 5 -- debug route dumping the environment.
app.get('/debug/env', (req, res) => {
  res.json(process.env);
});

// RULE 5 -- directory listing.
app.get('/debug/files', (req, res) => {
  res.json(fs.readdirSync('.'));
});

app.listen(3000);
