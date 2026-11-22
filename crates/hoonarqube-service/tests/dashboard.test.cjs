const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

class Element {
  constructor(document) {
    this.document = document;
    this.children = []; this.listeners = {}; this.value = ''; this.hidden = false;
    this.attributes = {}; this.controls = new Map();
    this.elements = {namedItem: (name) => {
      if (!this.controls.has(name)) {
        const control = new Element(document);
        control.options = [{value: 'open'}, {value: 'accepted'}, {value: 'resolved'}];
        this.controls.set(name, control);
      }
      return this.controls.get(name);
    }};
  }
  get firstChild() { return this.children[0]; }
  appendChild(child) { this.children.push(child); }
  append(...children) { this.children.push(...children); }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name]; }
  reportValidity() { return true; }
  scrollIntoView() {}
  focus() { this.document.activeElement = this; }
  get focused() { return this.document.activeElement === this; }
}

function dashboard() {
  const elements = new Map();
  const requests = [];
  const document = {
    activeElement: null,
    getElementById: (id) => get(id),
    createElement: () => new Element(document),
    createTextNode: (text) => ({textContent: text}),
  };
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, new Element(document));
    return elements.get(id);
  };
  const context = {
    document, Headers, Intl, Date, URLSearchParams,
    fetch(url) {
      return new Promise((resolve) => requests.push({url, respond(payload, status = 200, raw) {
        resolve({ok: status < 400, status, text: async () => raw === undefined ? JSON.stringify(payload) : raw});
      }}));
    },
  };
  const script = fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8');
  vm.runInNewContext(script.replace('  setSession(false);\n})();', '  globalThis.testState = state;\n  setSession(false);\n})();'), context);
  const fire = (id, event = 'change') => get(id).listeners[event]({preventDefault() {}, currentTarget: get(id)});
  const connect = (token) => { get('token').value = token; fire('connection-form', 'submit'); };
  return {get, requests, fire, connect, state: context.testState};
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
  ui.requests[2].respond({analyses: [], next_cursor: null});
  await settle();
  assert.equal(ui.get('history-panel').hidden, true);
  assert.equal(ui.get('scope-badge').children.map((child) => child.textContent).join(''), 'No project selected');
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
  ui.requests[2].respond({analyses: [], next_cursor: null});
  await settle();
  assert.equal(ui.get('history-panel').hidden, false);
  assert.equal(ui.get('history-empty').hidden, false);
});

function selectedReview(ui) {
  Object.assign(ui.state, {token: 'token', project: 'a', branch: 'main',
    analysis: {id: 1}, reviewAnalysisId: 1,
    selectedFinding: {identity: 'finding', kind: 'finding', review: {id: 2}}});
}

test('overlapping audit refreshes keep only the latest history response', async () => {
  const ui = dashboard(); selectedReview(ui);
  ui.fire('refresh-history-button', 'click');
  ui.fire('refresh-history-button', 'click');
  ui.requests[1].respond({history: [{actor: 'latest', version: 2}]});
  await settle();
  assert.equal(ui.get('audit-list').children.length, 1);
  const latest = ui.get('audit-list').children[0];
  ui.requests[0].respond({history: [{actor: 'stale', version: 1}]});
  await settle();
  assert.equal(ui.get('audit-list').children.length, 1);
  assert.equal(ui.get('audit-list').children[0], latest);
});

test('an old audit refresh error cannot replace current success', async () => {
  const ui = dashboard(); selectedReview(ui);
  ui.get('review-error').hidden = true;
  ui.fire('refresh-history-button', 'click');
  ui.fire('refresh-history-button', 'click');
  ui.requests[1].respond({history: [{actor: 'latest', version: 2}]});
  await settle();
  ui.requests[0].respond({error: {message: 'stale failure'}}, 500);
  await settle();
  assert.equal(ui.get('review-error').hidden, true);
  assert.equal(ui.get('audit-list').children.length, 1);
});

test('a current audit refresh error remains visible', async () => {
  const ui = dashboard(); selectedReview(ui);
  ui.get('review-error').hidden = true;
  ui.fire('refresh-history-button', 'click');
  ui.requests[0].respond({error: {message: 'current failure'}}, 500);
  await settle();
  assert.equal(ui.get('review-error').hidden, false);
});

test('reconnecting clears the previous project badge immediately', async () => {
  const ui = dashboard();
  ui.connect('token');
  ui.requests[0].respond({projects: [{project: 'a'}]});
  await settle();
  ui.get('project').value = 'a'; ui.fire('project');
  ui.requests[1].respond({branches: [{name: 'main'}]});
  await settle();
  assert.equal(ui.get('scope-badge').children.map((child) => child.textContent).join(''), 'a');
  ui.connect('new-token');
  assert.equal(ui.get('scope-badge').children.map((child) => child.textContent).join(''), 'No project selected');
});


async function loadedHistory(ui, analyses = [{id: 2, analyzed_at: '2026-10-02'}, {id: 1, analyzed_at: '2026-10-01'}], next_cursor = null) {
  ui.connect('token'); ui.requests[0].respond({projects: [{project: 'a'}]}); await settle();
  ui.get('project').value = 'a'; ui.fire('project');
  ui.requests[1].respond({branches: [{name: 'main'}]}); await settle();
  ui.get('branch').value = 'main'; ui.fire('branch'); ui.fire('scope-form', 'submit');
  ui.requests[2].respond({analyses, next_cursor}); await settle();
}
const nodeText = (node) => node.textContent ?? node.children.map(nodeText).join('');

test('malformed successful JSON is an error, never an authenticated empty project result', async () => {
  const ui = dashboard(); ui.connect('token');
  ui.requests[0].respond(null, 200, '<html>proxy error</html>'); await settle();
  assert.equal(ui.get('connection-error').hidden, false);
  assert.equal(ui.get('project').disabled, true);
  assert.equal(nodeText(ui.get('session-status')), 'Not connected');
});

test('missing analysis history is an error, never a clean empty branch', async () => {
  const ui = dashboard(); await loadedHistory(ui);
  // Restart history with an invalid envelope after valid rows were displayed.
  ui.fire('scope-form', 'submit'); ui.requests.at(-1).respond({}); await settle();
  assert.equal(ui.get('history-error').hidden, false);
  assert.equal(ui.get('history-empty').hidden, true);
  assert.equal(ui.get('history-body').children.length, 0);
});

test('history uses the service order and exposes native table buttons', async () => {
  const ui = dashboard(); await loadedHistory(ui);
  assert.equal(ui.requests[3].url, '/api/v1/projects/a/analyses/2/overview');
  const row = ui.get('history-body').children[0];
  assert.equal(row.getAttribute('role'), undefined);
  const button = row.children[0].children[0];
  assert.equal(button.type, 'button');
  assert.match(button.getAttribute('aria-label'), /analysis 2/i);
});

test('switching analysis clears old findings before the new response and on failure', async () => {
  const ui = dashboard(); await loadedHistory(ui);
  const firstId = 2;
  ui.requests[3].respond({analysis: {id: firstId, complete: true}}); await settle();
  ui.requests[4].respond({findings: [{identity: 'old', kind: 'finding', message: 'Old finding'}], next_cursor: null});
  await settle();
  assert.equal(ui.get('findings-list').children.length, 1);
  const targetRow = ui.get('history-body').children.find((row) => nodeText(row.children[2]) !== String(firstId));
  targetRow.listeners.click();
  assert.equal(ui.get('findings-list').children.length, 0);
  assert.equal(ui.get('findings-empty').hidden, true);
  ui.requests[5].respond({analysis: {id: 1, complete: true}}); await settle();
  assert.equal(ui.get('findings-list').children.length, 0);
  ui.requests[6].respond({error: 'unavailable'}, 500); await settle();
  assert.equal(ui.get('findings-list').children.length, 0);
  assert.equal(ui.get('findings-empty').hidden, true);
  assert.equal(ui.get('findings-error').hidden, false);
  assert.equal(ui.get('findings-retry').hidden, false);
  ui.fire('findings-retry', 'click');
  assert.equal(ui.requests[7].url, ui.requests[6].url);
  ui.requests[7].respond({findings: [], next_cursor: null}); await settle();
  assert.equal(ui.get('findings-empty').hidden, false);
  assert.equal(ui.get('findings-error').hidden, true);
  assert.equal(ui.get('findings-retry').hidden, true);
});

const analysisPage = () => Array.from({length: 25}, (_, index) => ({id: 30 - index}));
const findingPage = () => Array.from({length: 100}, (_, index) => ({identity: `row-${index}`, kind: 'finding'}));

test('history keeps rows and selection on a failed page and can move back from the end', async () => {
  const ui = dashboard(); const first = analysisPage();
  await loadedHistory(ui, first, 'opaque / +');
  assert.equal(ui.requests[2].url, '/api/v1/projects/a/analyses/page?limit=25&branch=main');
  ui.requests[3].respond({analysis: {id: 30, complete: true}}); await settle();
  ui.requests[4].respond({findings: [], next_cursor: null}); await settle();
  ui.get('history-next').focus();
  ui.fire('history-next', 'click'); ui.fire('history-next', 'click');
  assert.equal(ui.requests.length, 6);
  assert.equal(ui.get('history-next').getAttribute('aria-disabled'), 'true');
  assert.equal(new URL(ui.requests[5].url, 'https://example.test').searchParams.get('cursor'), 'opaque / +');
  ui.requests[5].respond({error: 'unavailable'}, 503); await settle();
  assert.equal(ui.get('history-error').hidden, false);
  assert.equal(ui.get('history-body').children.length, 25);
  assert.equal(ui.get('detail-panel').hidden, false);
  assert.equal(ui.get('history-next').getAttribute('aria-disabled'), 'false');
  ui.fire('history-next', 'click');
  assert.equal(ui.requests[6].url, ui.requests[5].url);
  ui.requests[6].respond({analyses: [{id: 5}], next_cursor: null}); await settle();
  assert.equal(ui.get('history-body').children.length, 1);
  assert.equal(nodeText(ui.get('history-count')), 'Page 2 · 1 analysis shown');
  assert.equal(ui.get('history-count').focused, true);
  assert.equal(ui.get('history-next').disabled, true);
  assert.equal(ui.get('history-error').hidden, true);
  assert.equal(ui.requests[7].url, '/api/v1/projects/a/analyses/5/overview');
  ui.fire('history-previous', 'click');
  assert.equal(ui.requests[8].url, ui.requests[2].url);
  ui.requests[8].respond({analyses: first, next_cursor: 'opaque / +'}); await settle();
  assert.equal(ui.requests[9].url, ui.requests[3].url);
  ui.requests[7].respond({error: 'old selection error'}, 404); await settle();
  assert.equal(ui.get('analysis-error').hidden, true);
  assert.equal(ui.get('history-previous').disabled, true);
});

test('changing the branch resets its cursor and discards late history', async () => {
  const ui = dashboard(); await loadedHistory(ui, analysisPage(), 'main-next');
  ui.fire('history-next', 'click');
  ui.get('branch').value = 'feature/a+b'; ui.fire('branch'); ui.fire('scope-form', 'submit');
  assert.equal(ui.requests[5].url, '/api/v1/projects/a/analyses/page?limit=25&branch=feature%2Fa%2Bb');
  ui.requests[5].respond({analyses: [], next_cursor: null}); await settle();
  ui.requests[4].respond({analyses: [{id: 80}], next_cursor: null}); await settle();
  assert.equal(ui.get('history-body').children.length, 0);
  assert.equal(ui.get('history-empty').hidden, false);
  assert.equal(ui.get('history-pagination').hidden, true);
});

test('findings show one page at a time, including a review on the last page', async () => {
  const ui = dashboard(); await loadedHistory(ui, [{id: 1}]);
  ui.requests[3].respond({analysis: {id: 1, complete: true}}); await settle();
  const first = findingPage();
  ui.requests[4].respond({findings: first, next_cursor: 'finding-next'}); await settle();
  assert.equal(ui.requests[4].url, '/api/v1/projects/a/analyses/1/findings/page?limit=100&include_review_versions=true');
  assert.equal(ui.get('findings-list').children.length, 100);
  ui.get('findings-next').focus();
  ui.fire('findings-next', 'click');
  assert.equal(ui.requests[5].url, '/api/v1/projects/a/analyses/1/findings/page?limit=100&cursor=finding-next&include_review_versions=true');
  const last = {identity: 'last', kind: 'finding', review_version: 4};
  ui.requests[5].respond({findings: [last], next_cursor: null}); await settle();
  assert.equal(ui.get('findings-count').focused, true);
  assert.equal(nodeText(ui.get('findings-count')), 'Page 2 · 1 finding shown');
  assert.equal(ui.get('findings-next').disabled, true);
  const cards = ui.get('findings-list').children;
  assert.equal(cards.length, 1);
  cards[0].children[1].children[0].listeners.click();
  const form = ui.get('ordinary-review-form');
  assert.equal(form.elements.namedItem('expected_version').value, '4');
  assert.equal(form.elements.namedItem('state').value, 'open');
  assert.equal(ui.requests.length, 6);
  form.elements.namedItem('reason').value = 'keep this draft';
  ui.fire('ordinary-review-form', 'submit');
  ui.requests[6].respond({error: 'conflict'}, 409); await settle();
  assert.equal(ui.requests[7].url, ui.requests[5].url);
  ui.requests[7].respond({findings: [{...last, review_version: 5}], next_cursor: null});
  await settle();
  assert.equal(form.elements.namedItem('expected_version').value, '5');
  assert.equal(form.elements.namedItem('reason').value, 'keep this draft');
  ui.fire('findings-previous', 'click');
  assert.equal(ui.requests[8].url, ui.requests[4].url);
  ui.requests[8].respond({findings: first, next_cursor: 'finding-next'}); await settle();
  assert.equal(ui.get('review-panel').hidden, true);
  assert.equal(ui.get('findings-list').children.length, 100);
});

test('late findings cannot repaint a different analysis or show its error', async () => {
  const ui = dashboard(); await loadedHistory(ui);
  ui.requests[3].respond({analysis: {id: 2, complete: true}}); await settle();
  ui.requests[4].respond({findings: findingPage(), next_cursor: 'old-next'}); await settle();
  ui.fire('findings-next', 'click');
  ui.get('history-body').children[1].listeners.click();
  ui.requests[6].respond({analysis: {id: 1, complete: true}}); await settle();
  assert.ok(!ui.requests[7].url.includes('cursor='));
  ui.requests[7].respond({findings: [], next_cursor: null}); await settle();
  ui.requests[5].respond({error: 'stale page'}, 503); await settle();
  assert.equal(ui.get('findings-empty').hidden, false);
  assert.equal(ui.get('findings-error').hidden, true);
  assert.equal(ui.get('findings-pagination').hidden, true);
});

test('review saves reject duplicate submissions while retaining the draft on failure', async () => {
  const ui = dashboard(); selectedReview(ui);
  const form = ui.get('ordinary-review-form');
  form.elements.namedItem('identity').value = 'finding';
  form.elements.namedItem('reason').value = 'A thoughtful reason';
  form.elements.namedItem('expected_version').value = '0';
  ui.fire('ordinary-review-form', 'submit'); ui.fire('ordinary-review-form', 'submit');
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.get('ordinary-save-button').disabled, true);
  ui.requests[0].respond({error: 'temporarily unavailable'}, 500); await settle();
  assert.equal(form.elements.namedItem('reason').value, 'A thoughtful reason');
  assert.equal(ui.get('ordinary-save-button').disabled, false);
});

test('whitespace-only review reasons are refused without a request', () => {
  const ui = dashboard(); selectedReview(ui);
  ui.get('ordinary-review-form').elements.namedItem('reason').value = '   ';
  ui.fire('ordinary-review-form', 'submit');
  assert.equal(ui.requests.length, 0);
  assert.equal(ui.get('review-error').hidden, false);
});


test('a version conflict refreshes the current review without deleting the reason draft', async () => {
  const ui = dashboard(); selectedReview(ui);
  const form = ui.get('ordinary-review-form');
  form.elements.namedItem('identity').value = 'finding';
  form.elements.namedItem('reason').value = 'Keep this draft';
  form.elements.namedItem('expected_version').value = '0';
  ui.fire('ordinary-review-form', 'submit');
  ui.requests[0].respond({error: 'conflict'}, 409); await settle();
  const review = {id: 2, identity: 'finding', kind: 'finding', state: 'accepted', version: 3};
  ui.requests[1].respond({findings: [{identity: 'finding', kind: 'finding', review}], next_cursor: null});
  await settle();
  ui.requests[2].respond({history: []}); await settle();
  assert.equal(form.elements.namedItem('reason').value, 'Keep this draft');
  assert.equal(form.elements.namedItem('expected_version').value, '3');
  assert.equal(form.elements.namedItem('state').value, 'accepted');
  assert.match(nodeText(ui.get('review-error')), /version conflict/);
  assert.equal(ui.get('ordinary-save-button').disabled, false);
});

test('a successful save updates its version and preserves a newer draft entered while saving', async () => {
  const ui = dashboard(); selectedReview(ui);
  ui.state.findings = [ui.state.selectedFinding];
  const form = ui.get('ordinary-review-form');
  form.elements.namedItem('identity').value = 'finding';
  form.elements.namedItem('reason').value = 'Submitted reason';
  form.elements.namedItem('expected_version').value = '0';
  ui.fire('ordinary-review-form', 'submit');
  form.elements.namedItem('reason').value = 'A newer draft';
  ui.requests[0].respond({review: {id: 2, identity: 'finding', kind: 'finding', analysis_id: 1, version: 1, state: 'accepted'}});
  await settle(); ui.requests[1].respond({history: []}); await settle();
  assert.equal(form.elements.namedItem('expected_version').value, '1');
  assert.equal(form.elements.namedItem('reason').value, 'A newer draft');
  assert.equal(ui.get('review-message').hidden, false);
  assert.equal(ui.get('ordinary-save-button').disabled, false);
});

test('an invalid save response cannot claim success or discard a draft', async () => {
  const ui = dashboard(); selectedReview(ui);
  const form = ui.get('ordinary-review-form');
  form.elements.namedItem('identity').value = 'finding';
  form.elements.namedItem('reason').value = 'Keep me';
  form.elements.namedItem('expected_version').value = '0';
  ui.fire('ordinary-review-form', 'submit'); ui.requests[0].respond({}); await settle();
  assert.equal(ui.get('review-message').hidden, true);
  assert.equal(ui.get('review-error').hidden, false);
  assert.equal(form.elements.namedItem('reason').value, 'Keep me');
  assert.equal(ui.get('ordinary-save-button').disabled, false);
});

test('analysis selection retains the existing history button and updates its pressed state', async () => {
  const ui = dashboard(); await loadedHistory(ui);
  const row = ui.get('history-body').children[0];
  const button = row.children[0].children[0]; button.focus();
  ui.requests[3].respond({analysis: {id: 2, complete: true}}); await settle();
  assert.equal(ui.get('history-body').children[0].children[0].children[0], button);
  assert.equal(button.getAttribute('aria-pressed'), 'true');
  assert.equal(button.focused, true);
});


test('a pending connection or transport failure can always clear its token by disconnecting', async () => {
  const ui = dashboard(); ui.connect('token');
  assert.equal(ui.get('disconnect-button').disabled, false);
  ui.requests[0].respond({error: 'unavailable'}, 503); await settle();
  assert.equal(ui.get('disconnect-button').disabled, false);
  assert.equal(nodeText(ui.get('project').children[0]), 'Reconnect to load projects');
  ui.fire('disconnect-button', 'click');
  assert.equal(ui.state.token, null);
  assert.equal(ui.get('token').value, '');
});

test('changing projects updates scope immediately and branch loading failure offers a retry', async () => {
  const ui = dashboard(); ui.connect('token');
  ui.requests[0].respond({projects: [{project: 'a'}, {project: 'b'}]}); await settle();
  ui.get('project').value = 'a'; ui.fire('project');
  ui.requests[1].respond({branches: [{name: 'main'}]}); await settle();
  ui.get('project').value = 'b'; ui.fire('project');
  assert.equal(nodeText(ui.get('scope-badge')), 'b');
  assert.equal(nodeText(ui.get('branch').children[0]), 'Loading branches…');
  ui.requests[2].respond({error: 'unavailable'}, 503); await settle();
  assert.match(nodeText(ui.get('branch').children[0]), /retry/);
  assert.equal(ui.get('branch').disabled, true);
});


async function renderedMetrics(metrics, duplication) {
  const ui = dashboard(); await loadedHistory(ui, [{id: 1}]);
  ui.requests[3].respond({analysis: {id: 1, complete: true, metrics, duplication}}); await settle();
  return ui.get('metrics-grid').children.map((card) => card.children.map(nodeText));
}

test('metric cards show readable common labels and duplication density in percent units', async () => {
  const cards = await renderedMetrics({code_lines: 0, comment_lines: 12, files: 2, lines: 100},
    {duplicated_blocks: 3, duplicated_files: 2, duplicated_lines: 10, duplicated_lines_density: 12.3456});
  assert.deepEqual(cards, [['Code lines', '0'], ['Comment lines', '12'], ['Files', '2'], ['Lines', '100'],
    ['Duplicated blocks', '3'], ['Duplicated files', '2'], ['Duplicated lines', '10'], ['Duplication density', '12.35%']]);
});

test('metric formatting preserves zero, missing measurements and unknown metric values', async () => {
  const cards = await renderedMetrics({future_metric: 7, custom_state: 'unknown', nullable_metric: null, constructor: 4},
    {duplicated_lines_density: 0, duplicated_blocks: null});
  assert.deepEqual(cards, [['future_metric', '7'], ['custom_state', 'unknown'], ['nullable_metric', 'Not measured'],
    ['constructor', '4'], ['Duplication density', '0%'], ['Duplicated blocks', 'Not measured']]);
  const unavailable = await renderedMetrics({}, {duplicated_lines_density: null});
  assert.deepEqual(unavailable, [['Duplication density', 'Not measured']]);
  const nonnumeric = await renderedMetrics({}, {duplicated_lines_density: 'unknown'});
  assert.deepEqual(nonnumeric, [['Duplication density', 'unknown']]);
});

test('gate details identify only conditions compared with one decimal place', async () => {
  const ui = dashboard(); await loadedHistory(ui, [{id: 1}]);
  const common = {scope: 'overall', metric: 'line_coverage', operator: 'gte', threshold: 66.7};
  const conditions = [
    {...common, actual: 66.7, precision: 'one_decimal', status: 'pass'},
    {...common, actual: 66.66666666666667, status: 'fail'},
  ];
  ui.requests[3].respond({analysis: {id: 1, complete: true, gate: {status: 'fail', conditions}}}); await settle();
  const [rounded, full] = ui.get('gates-list').children.map(nodeText);
  assert.match(rounded, /66\.7 \(rounded to one decimal place\) gte 66\.7/);
  assert.match(full, /66\.66666666666667 gte 66\.7/);
  assert.doesNotMatch(full, /rounded/);
});
