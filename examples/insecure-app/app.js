// DELIBERATELY INSECURE test fixture for VulnSight AI. Never deploy this.
const express = require('express');
const { exec } = require('child_process');
const app = express();

// Reflected XSS: user input written straight into the response.
app.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

// Command injection: user input concatenated into a shell command.
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

// eval of user input.
app.post('/calc', (req, res) => {
  res.send(String(eval(req.body.expression)));
});

app.listen(3000);
