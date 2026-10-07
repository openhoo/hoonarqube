const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

class Element {
  constructor() { this.children = []; this.listeners = {}; this.value = ''; this.hidden = false; }
  get firstChild() { return this.children[0]; }
  appendChild(child) { this.children.push(child); }
  append(...children) { this.children.push(...children); }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  focus() {}
}

function dashboard() {
  const elements = new Map();
  const requests = [];
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const context = {
    document: {getElementById: get, createElement: () => new Element(), createTextNode: (text) => ({textContent: text})},
    Headers, Intl, Date,
    fetch(url) {
      return new Promise((resolve) => requests.push({url, respond(payload, status = 200) {
        resolve({ok: status < 400, status, text: async () => JSON.stringify(payload)});
      }}));
    },
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8'), context);
  const fire = (id, event = 'change') => get(id).listeners[event]({preventDefault() {}, currentTarget: get(id)});
  const connect = (token) => { get('token').value = token; fire('connection-form', 'submit'); };
  return {get, requests, fire, connect};
}
const settle = () => new Promise(setImmediate);
const optionValues = (node) => node.children.map((child) => child.value);

test('an old connection response cannot overwrite a newer connection', async () => {
  const ui = dashboard();
  ui.connect('old-token');
  ui.connect('new-token');
  ui.requests[1].respond({projects: [{project: 'new-project'}]});
  await settle();
  ui.requests[0].respond({projects: [{project: 'old-project'}]});
  await settle();
  assert.deepEqual(optionValues(ui.get('project')), ['', 'new-project']);
});

test('an old authentication error cannot disconnect a newer session', async () => {
  const ui = dashboard();
  ui.connect('old-token');
  ui.connect('new-token');
  ui.requests[1].respond({projects: [{project: 'new-project'}]});
  await settle();
  ui.requests[0].respond({error: {message: 'old failure'}}, 401);
  await settle();
  assert.equal(ui.get('project').disabled, false);
  assert.equal(ui.get('connection-error').hidden, true);
});

test('branch responses are bound to the selected project', async () => {
  const ui = dashboard();
  ui.connect('token');
  ui.requests[0].respond({projects: [{project: 'a'}, {project: 'b'}]});
  await settle();
  ui.get('project').value = 'a'; ui.fire('project');
  ui.get('project').value = 'b'; ui.fire('project');
  ui.requests[2].respond({branches: [{name: 'b-main'}]});
  await settle();
  ui.requests[1].respond({branches: [{name: 'a-main'}]});
  await settle();
  assert.deepEqual(optionValues(ui.get('branch')), ['', 'b-main']);
});

test('disconnect discards pending project responses', async () => {
  const ui = dashboard();
  ui.connect('token');
  ui.fire('disconnect-button', 'click');
  ui.requests[0].respond({projects: [{project: 'private-project'}]});
  await settle();
  assert.equal(ui.get('disconnect-button').disabled, true);
  assert.deepEqual(optionValues(ui.get('project')), ['']);
});

test('disconnect keeps pending analysis history hidden', async () => {
  const ui = dashboard();
  ui.connect('token');
  ui.requests[0].respond({projects: [{project: 'a'}]});
  await settle();
  ui.get('project').value = 'a'; ui.fire('project');
  ui.requests[1].respond({branches: [{name: 'main'}]});
  await settle();
  ui.get('branch').value = 'main'; ui.fire('branch');
  ui.fire('scope-form', 'submit');
  ui.fire('disconnect-button', 'click');
  ui.requests[2].respond({analyses: []});
  await settle();
  assert.equal(ui.get('history-panel').hidden, true);
});

test('a current connection failure remains visible', async () => {
  const ui = dashboard();
  ui.connect('bad-token');
  ui.requests[0].respond({error: {message: 'invalid credential'}}, 401);
  await settle();
  assert.equal(ui.get('connection-error').hidden, false);
  assert.equal(ui.get('project').disabled, true);
  assert.equal(ui.get('disconnect-button').disabled, true);
});

test('the current selected scope can render an empty history', async () => {
  const ui = dashboard();
  ui.connect('token');
  ui.requests[0].respond({projects: [{project: 'a'}]});
  await settle();
  ui.get('project').value = 'a'; ui.fire('project');
  ui.requests[1].respond({branches: [{name: 'main'}]});
  await settle();
  ui.get('branch').value = 'main'; ui.fire('branch');
  ui.fire('scope-form', 'submit');
  ui.requests[2].respond({analyses: []});
  await settle();
  assert.equal(ui.get('history-panel').hidden, false);
  assert.equal(ui.get('history-empty').hidden, false);
});
