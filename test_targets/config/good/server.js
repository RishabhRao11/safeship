// Correctly configured Express app. Zero findings expected.
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

app.use(helmet());
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));

const loginLimiter = rateLimit({ windowMs: 60000, max: 5 });

app.post('/api/login', loginLimiter, (req, res) => {
  res.cookie('session', 'abc', { httpOnly: true, secure: true });
  res.json({ ok: true });
});

app.listen(3000);
