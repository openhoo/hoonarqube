'use strict';

const policy = require('./jev-triage-policy.cjs');
const ENDPOINT = 'http://100.114.173.91:9138/v1/decisions';

async function evaluate(payload, { key, fetchImpl = fetch } = {}) {
  if (typeof key !== 'string' || !key.trim()) throw new Error('Jev intake key is not configured.');
  let response;
  try {
    response = await fetchImpl(ENDPOINT, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(110000),
      headers: { Authorization: `Bearer ${key.trim()}`, 'Content-Type': 'application/json',
        'User-Agent': 'Hoonarqube-Jev-Triage/1.0 (+https://github.com/openhoo/hoonarqube)' },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new Error('Jev intake request failed or timed out; no retry or alternative model was attempted.');
  }
  if (!response.ok) {
    const responseKind = response.headers.get('cf-mitigated') === 'challenge' ? 'edge challenge' :
      response.headers.get('content-type')?.includes('text/html') ? 'HTML edge response' : 'API response';
    throw new Error(`Jev intake HTTP ${response.status} (${responseKind}); response details suppressed.`);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 131072) throw new Error('Jev response exceeds the bounded response size.');
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    await reader.cancel();
    throw new Error('Jev returned an unreadable or oversized response.');
  }
}

async function read(github, request) {
  const issue = (await github.rest.issues.get(request)).data;
  const comments = await github.paginate(github.rest.issues.listComments, { ...request, per_page: 100 });
  const events = await github.paginate(github.rest.issues.listEventsForTimeline, { ...request, per_page: 100 });
  if (!Array.isArray(comments) || !Array.isArray(events)) throw new Error('Complete issue context is unavailable.');
  return { issue, comments, events };
}

function unchanged(left, right) {
  return left.issue.state === right.issue.state &&
    policy.labels(left.issue).join() === policy.labels(right.issue).join() &&
    policy.notice(left.comments)?.body === policy.notice(right.comments)?.body &&
    policy.snapshot(left.issue, left.comments).fingerprint === policy.snapshot(right.issue, right.comments).fingerprint &&
    JSON.stringify(left.events) === JSON.stringify(right.events);
}

async function upsert(github, request, prior, body) {
  if (prior) {
    const result = await github.rest.issues.updateComment({ owner: request.owner, repo: request.repo, comment_id: prior.id, body });
    return { ...prior, ...result.data, body };
  }
  const result = await github.rest.issues.createComment({ ...request, body });
  return result.data;
}

async function run({ github, context, core, key = process.env.HOONARQUBE_JEV_KEY,
  enabled = process.env.HOONARQUBE_JEV_TRIAGE_ENABLED === 'true', evaluator = evaluate, dryRun = false } = {}) {
  if (!enabled) return { skipped: true, reason: 'disabled' };
  if (context.repo?.owner !== 'openhoo' || context.repo?.repo !== 'hoonarqube') return { skipped: true, reason: 'repository' };
  if (context.payload?.issue?.pull_request) return { skipped: true, reason: 'pull-request' };
  if (context.eventName === 'issue_comment' && context.payload?.comment?.user?.type === 'Bot') return { skipped: true, reason: 'bot-comment' };
  const number = context.payload?.issue?.number ?? Number(context.payload?.inputs?.issue_number);
  if (!Number.isSafeInteger(number) || number < 1) throw new Error('A positive issue number is required.');
  const request = { ...context.repo, issue_number: number };
  const before = await read(github, request);
  const { issue, comments } = before;
  if (issue.pull_request || issue.state !== 'open') return { skipped: true, reason: 'not-open-issue' };
  const prior = policy.notice(comments);
  const currentStates = policy.STATES.filter((name) => policy.labels(issue).includes(name));
  if ((currentStates.length > 1 && !policy.recoverableState(issue, prior, before.events)) || currentStates.some((name) => ['ready-for-agent', 'wontfix'].includes(name))) {
    return { skipped: true, reason: 'maintainer-state' };
  }
  if (!policy.intake.validateIssueBody(issue.body).valid) return { skipped: true, reason: 'structural-intake-required' };
  const { state, fingerprint } = policy.snapshot(issue, comments);
  if (prior?.metadata.fingerprint === fingerprint && prior.metadata.applied === true) return { skipped: true, reason: 'already-triaged' };
  const raw = await evaluator({ model: policy.MODEL, state, questions: policy.QUESTIONS }, { key });
  const decisions = policy.validateResponse(raw);
  if (decisions.security.choice !== 'ordinary') return { skipped: true, reason: 'private-or-uncertain-security-review' };
  const changes = policy.plan(issue, decisions, prior, before.events);
  if (changes.skipped) return changes;
  const noteArgs = { fingerprint, decisions, changes, sourceSha: context.sha };
  if (dryRun) return { skipped: false, dryRun: true, decisions, changes, body: policy.buildNote({ ...noteArgs, applied: true }) };
  const refreshed = await read(github, request);
  if (!unchanged(before, refreshed)) throw new Error('Issue changed during Jev evaluation; no mutations applied.');
  // Persist ownership intent before writing labels. A retry can recover from a
  // partial write; no issue body, state=closed, assignment or ready label is sent.
  const savedNote = await upsert(github, request, prior, policy.buildNote({ ...noteArgs, applied: false }));
  if (changes.add.length) await github.rest.issues.addLabels({ ...request, labels: changes.add });
  for (const name of changes.remove) await github.rest.issues.removeLabel({ ...request, name });
  const after = await read(github, request);
  const expected = new Set([...policy.labels(issue), ...changes.add]);
  for (const name of changes.remove) expected.delete(name);
  if (policy.labels(after.issue).join() !== [...expected].sort().join() || after.issue.state !== 'open' ||
    policy.snapshot(after.issue, after.comments).fingerprint !== fingerprint) {
    throw new Error('Triage readback differs from the planned result; inspect the issue before retrying.');
  }
  const finalBody = policy.buildNote({ ...noteArgs, applied: true });
  await upsert(github, request, savedNote, finalBody);
  const verified = (await github.rest.issues.getComment({ owner: request.owner, repo: request.repo, comment_id: savedNote.id })).data;
  if (verified.body !== finalBody) throw new Error('Triage comment readback failed.');
  core?.info(`Jev intake applied and read back for issue #${number}; no implementation was authorized.`);
  return { skipped: false, issueNumber: number, decisions, changes };
}

module.exports = { ENDPOINT, evaluate, run };
