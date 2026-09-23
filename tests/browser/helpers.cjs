const { JSDOM } = require('jsdom');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
const adapterCode = fs.readFileSync(path.join(__dirname, '../../extension/adapters.js'), 'utf8');
function page(host, html) {
  const dom = new JSDOM(html, { url: `https://${host}/read?token=secret#message-1`, runScripts: 'outside-only' });
  dom.window.eval(adapterCode);
  return dom;
}
function extract(dom) { return dom.window.ShieldDomeMail.extract(dom.window.document, dom.window.location); }
function gmail(subject = '通知', body = '请检查今日的项目安排。') {
  return `<h2 class="hP">${subject}</h2><div class="adn"><span class="gD" email="sender@example.com">Sender</span><div class="a3s aiL">${body}</div></div>`;
}
module.exports = { page, extract, gmail, webcrypto };
