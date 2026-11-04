'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { extractLinksAndForms } = require('../src/adapters/dast/crawler');

test('extractLinksAndForms extracts internal links and form parameters', () => {
  const html = `
    <html>
      <body>
        <a href="/about">About Us</a>
        <a href="/products?category=security&page=1">Products</a>
        <a href="https://external-phishing.com">External</a>
        <form action="/login" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="hidden" name="csrf_token">
        </form>
      </body>
    </html>
  `;
  const baseOrigin = 'https://mysite.com';

  const { links, forms } = extractLinksAndForms(html, baseOrigin);

  assert.ok(links.includes('/about'));
  assert.ok(links.includes('/products?category=security&page=1'));
  assert.equal(links.some((l) => l.includes('external-phishing.com')), false);

  assert.equal(forms.length, 1);
  const loginForm = forms[0];
  assert.equal(loginForm.path, '/login');
  assert.equal(loginForm.method, 'POST');
  assert.deepEqual(loginForm.parameters, ['username', 'password', 'csrf_token']);
});
