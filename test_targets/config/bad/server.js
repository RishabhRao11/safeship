// Express app, planted fixture.
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

app.post('/api/login', (req, res) => {
  res.cookie('session', 'abc', { httpOnly: false });
  res.json({ ok: true });
});

app.post('/api/password/reset', (req, res) => res.json({ ok: true }));

app.listen(3000);
