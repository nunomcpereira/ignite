'use strict';

/**
 * Reshapes Ignite's flat issue list (same input as lib/sarif.js's
 * buildSarif) into GitHub Actions workflow-command annotations
 * (`::error file=...,line=...::message`) — closes part of the "single
 * output format (SARIF only)" gap against fallow.tools' github-annotations/
 * github-summary formats (see project memory). Unlike the SARIF upload
 * path (which needs the separate "upload SARIF" step and lands findings in
 * the Security tab, visible only to users with code-scanning read access),
 * workflow commands printed to a job's own stdout appear inline on the
 * "Files changed" / job log view for anyone who can see the run — no extra
 * permissions, no upload step, just `cat` the output during a workflow.
 *
 * An overridden issue is skipped entirely — same "no longer an open
 * blocker" logic buildSarif's note-level downgrade encodes, but an
 * annotation has no severity below warning/error to downgrade to, so
 * omitting it is the closest equivalent.
 */

// error/warning are the only levels workflow commands: notice exists too,
// but Ignite has no severity below 'warning' to map it to.
function annotationLevel(issue) {
  return issue.severity === 'error' ? 'error' : 'warning';
}

// Workflow-command property/data values can't contain raw CR/LF/%, or the
// command parser misreads them — GitHub's own escaping table.
function escapeData(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function escapeProperty(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')
    .replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function toAnnotationLine(issue) {
  const level = annotationLevel(issue);
  const props = [];
  if (issue.file) props.push(`file=${escapeProperty(issue.file)}`);
  if (Number.isInteger(issue.line) && issue.line > 0) props.push(`line=${issue.line}`);
  props.push(`title=Ignite: ${escapeProperty(issue.category || 'finding')}`);
  const propStr = props.join(',');
  return `::${level} ${propStr}::${escapeData(issue.summary || '(no summary)')}`;
}

function buildGithubAnnotations(issues) {
  return issues
    .filter((issue) => issue.status !== 'overridden')
    .map(toAnnotationLine)
    .join('\n');
}

module.exports = { buildGithubAnnotations, annotationLevel };
