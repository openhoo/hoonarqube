'use strict';

// Read a narrowly scoped key from stdin; output only fixture IDs and typed
// decisions. Never print the request header, key, response body or exceptions.
const fs = require('node:fs');
const { evaluate } = require('./issue-jev-triage.cjs');
const { MODEL, QUESTIONS, validateResponse } = require('./jev-triage-policy.cjs');
const fixtures = require('./jev-triage-fixtures.json');

async function main() {
  const key = fs.readFileSync(0, 'utf8').trim();
  const results = [];
  for (const fixture of fixtures) {
    try {
      const response = await evaluate({ model: MODEL, state: fixture.state, questions: QUESTIONS }, { key });
      const decisions = validateResponse(response);
      const mismatches = Object.entries(fixture.expected).filter(([id, expected]) => decisions[id].choice !== expected)
        .map(([id, expected]) => ({ question: id, expected, actual: decisions[id].choice, confidence: decisions[id].confidence }));
      const abstentions = mismatches.filter((mismatch) => mismatch.actual === 'unknown');
      const confidentErrors = mismatches.filter((mismatch) => mismatch.actual !== 'unknown');
      const result = { fixture: fixture.id, model: response.model, exact_match: mismatches.length === 0,
        safety_pass: confidentErrors.length === 0, automated: decisions.security.choice === 'ordinary',
        abstentions, confident_errors: confidentErrors,
        decisions: Object.fromEntries(Object.entries(decisions).map(([id, value]) => [id, value.choice])) };
      results.push(result);
      console.log(JSON.stringify(result));
    } catch (error) {
      const safeMessage = /^(Jev intake HTTP \d+; response details suppressed\.|Jev intake request failed or timed out; no retry or alternative model was attempted\.|Unexpected Jev model or answer set\.|Malformed Jev choice answer\.|Invalid Jev probabilities\.|Jev returned an unreadable or oversized response\.)$/.test(error.message) ? error.message : 'Model request or typed validation failed; details suppressed.';
      console.log(JSON.stringify({ fixture: fixture.id, passed: false, error: safeMessage }));
      process.exitCode = 1;
      return;
    }
  }
  const summary = { total: results.length, exact_matches: results.filter((result) => result.exact_match).length,
    safe_outcomes: results.filter((result) => result.safety_pass).length,
    automated_cases: results.filter((result) => result.automated).length,
    manual_cases: results.filter((result) => !result.automated).length,
    confident_errors: results.reduce((count, result) => count + result.confident_errors.length, 0),
    abstentions: results.reduce((count, result) => count + result.abstentions.length, 0) };
  console.log(JSON.stringify(summary));
  if (summary.confident_errors > 0 || summary.automated_cases === 0) process.exitCode = 1;
}
main().catch(() => { console.error('Jev evaluation failed; protected details suppressed.'); process.exitCode = 1; });
