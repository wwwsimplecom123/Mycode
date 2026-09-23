const test = require('node:test');
const assert = require('node:assert/strict');
const { page, extract, gmail } = require('./helpers.cjs');
test('Gmail limits links and body to the last visible message', () => {
  const dom = page('mail.google.com', gmail('项目', '旧邮件') + '<div class="adn"><span class="gD" email="new@example.com">New</span><div class="a3s">新邮件<a href="https://example.com/login">登录</a></div></div><div class="adn" hidden><span class="gD" email="hidden@example.com"></span><div class="a3s">隐藏邮件</div></div><a href="https://navigation.example">设置</a>');
  const result = extract(dom);
  assert.equal(result.sender, 'new@example.com');
  assert.equal(result.body_text, '新邮件登录');
  assert.equal(result.links.length, 1);
  assert.equal(result.page_url, 'https://mail.google.com/read');
  assert.ok(!JSON.stringify(result).includes('secret'));
});
for (const host of ['mail.qq.com', 'exmail.qq.com']) test(`${host} reads nested same-origin mail frames`, () => {
  const dom = page(host, '<iframe id="mainFrame"></iframe>');
  const inner = dom.window.document.querySelector('iframe').contentDocument;
  inner.body.innerHTML = '<h2 id="subject">QQ通知</h2><span id="fromaddr" addr="qq@example.com">QQ</span><iframe id="mailContent"></iframe>';
  inner.querySelector('iframe').contentDocument.body.innerHTML = '你好<a href="https://example.com">查看</a>';
  const result = extract(dom);
  assert.equal(result.subject, 'QQ通知');
  assert.equal(result.sender, 'qq@example.com');
  assert.equal(result.body_text, '你好查看');
});
for (const host of ['mail.163.com', 'mail.126.com', 'mail.yeah.net', 'qiye.163.com']) test(`${host} reads mail content frames`, () => {
  const dom = page(host, '<h1 class="nui-mail-detail-subject">网易通知</h1><span class="nui-mail-detail-sender" data-email="sender@163.com">发送者</span><iframe id="_mail_emailcontent_12"></iframe>');
  dom.window.document.querySelector('iframe').contentDocument.body.innerHTML = '<p>网易正文</p>';
  assert.equal(extract(dom).body_text, '网易正文');
  assert.equal(extract(dom).mail_client, 'browser-extension:netease-mail');
});
test('inbox, unsupported hosts and unrecognized frames are not collected', () => {
  assert.equal(extract(page('mail.qq.com', '<div>发件人：someone 主题：列表</div><iframe></iframe>')), null);
  assert.equal(extract(page('mail.google.com.evil.test', gmail())), null);
  assert.equal(extract(page('mail.qq.com', '<h2 id="subject">标题</h2><span id="fromaddr">sender</span><div id="mailContent" hidden>隐藏正文</div>')), null);
  assert.equal(extract(page('mail.qq.com', '<h2 id="subject">标题</h2><span id="fromaddr">sender</span><iframe id="mailContent" src="https://unavailable.example"></iframe>')), null);
});
test('body cannot forge sender or subject selectors', () => {
  const dom = page('mail.qq.com', '<div id="mailContent"><h2 id="subject">伪造标题</h2><span id="fromaddr">伪造身份</span>内容</div>');
  assert.equal(extract(dom), null);
});
for (const [host, html] of [
  ['outlook.live.com', '<h2 role="heading">通知</h2><span data-testid="SenderPersona">sender@example.com</span><div role="document">正文</div>'],
  ['webmail.chinaccs.cn', '<h2 id="subject">通知</h2><span class="sender">sender@example.com</span><div id="mailContent">正文</div>'],
]) test(`${host} retains adapter`, () => assert.equal(extract(page(host, html)).body_text, '正文'));
test('manifest loads adapters first and covers every declared host', () => {
  const manifest = require('../../extension/manifest.json');
  assert.deepEqual(manifest.content_scripts[0].js, ['adapters.js', 'content.js']);
  assert.ok(manifest.content_scripts[0].matches.includes('https://mail.yeah.net/*'));
});
test('Gmail does not borrow a sender from an earlier message while rendering', () => {
  const dom = page('mail.google.com', gmail() + '<div class="adn"><div class="a3s">新消息尚未加载发件人</div></div>');
  assert.equal(extract(dom), null);
});
