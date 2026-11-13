/* Console additions: executive summary, business-unit pages, printable report,
   deadline chart, table search and sorting, theme switch, busy banner.
   Loaded after app.js; it extends the pages defined there. */

/* ---------- posture summary ---------- */
function posture() {
  const adopted = S.controls.filter(c => c.accepted);
  let tot = 0, comp = 0;
  adopted.forEach(c => { tot += Object.values(c.counts).reduce((a, b) => a + b, 0); comp += (c.counts.compliant || 0) + (c.counts.exception || 0); });
  const compliance = tot ? comp / tot : null;
  const open = S.vulns.filter(v => v.status === 'open');
  const overdue = open.filter(v => v.overdue).length;
  const crit = open.filter(v => v.severity === 'critical' || v.severity === 'zero-day').length;
  const above = S.bus.filter(b => b.score > b.goal_line).length;
  const pend = S.tickets.filter(t => t.type === 'config_approval' && t.status !== 'closed').length;
  const parts = [];
  const p1 = compliance == null ? 40 : Math.round((1 - compliance) * 40);
  parts.push([compliance == null ? 'Baseline not implemented yet' : `Baseline compliance is ${Math.round(compliance * 100)}%`, p1, 40]);
  const p2 = Math.round(above / S.bus.length * 30);
  parts.push([`${above} of ${S.bus.length} business units above their goal line`, p2, 30]);
  const p3 = Math.min(20, crit * 4 + overdue * 2);
  parts.push([`${crit} critical or zero-day vulnerabilities open, ${overdue} past deadline`, p3, 20]);
  const p4 = Math.min(10, pend * 2);
  parts.push([`${pend} sensitive settings waiting for a decision`, p4, 10]);
  const score = Math.max(0, 100 - p1 - p2 - p3 - p4);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'E';
  return { score, grade, parts, compliance, overdue, crit, above, pend, open: open.length };
}
function urgent() {
  const out = [], open = S.vulns.filter(v => v.status === 'open');
  S.servers.filter(s => s.open_vulns).forEach(s => {
    const mine = open.filter(v => v.instance_id === s.id);
    const c = mine.filter(v => v.severity === 'critical' || v.severity === 'zero-day').length, od = mine.filter(v => v.overdue).length;
    out.push({ w: s.risk + c * 50 + od * 30, title: `Patch ${s.name}`, nav: 'patching',
      why: `${mine.length} open vulnerabilities${c ? `, ${c} critical` : ''}${od ? `, ${od} past deadline` : ''}. Owner: ${s.owner || 'unassigned'}.` });
  });
  S.tickets.filter(t => t.type === 'config_approval' && t.status !== 'closed').forEach(t => {
    const i = S.issues.find(x => x.id === t.ref_id) || {};
    out.push({ w: ({ critical: 400, high: 200, medium: 80, low: 20 })[t.severity] || 50, nav: 'drift',
      title: `Decide on ${i.control_id} for ${i.resource_name}`, why: `${i.detail}. Waiting for ${t.assignee}.` });
  });
  S.bus.filter(b => b.held).forEach(b => out.push({ w: 150, nav: 'patching', title: `Release the downtime hold for ${b.name}`, why: `Scheduled patching is skipping this unit: “${b.held}”.` }));
  return out.sort((a, b) => b.w - a.w).slice(0, 3);
}
function execCard(forPrint) {
  const p = posture(), u = urgent();
  const tone = p.grade <= 'B' ? 'ok' : p.grade === 'C' ? 'wait' : 'bad';
  return `<div class="card exec">
    <div class="gradebox"><div class="grade ${tone}">${p.grade}</div><div><b>${p.score}<small> / 100</small></b><span>Posture score</span></div></div>
    <div class="why"><h2>What is holding the score down</h2>
      ${p.parts.map(([t, lost, max]) => `<div class="ded"><span>${esc(t)}</span><div class="dbar"><i style="width:${lost / max * 100}%"></i></div><b>${lost ? '−' + lost : '0'}</b></div>`).join('')}
      <div class="hint" style="margin-top:8px">A summary measure made for this console: 100 minus points for baseline gaps (up to 40), units above goal (30), critical or overdue vulnerabilities (20) and undecided approvals (10).</div></div>
    <div class="todo"><h2>Most urgent</h2>
      ${u.map((a, i) => `<div class="act"><em>${i + 1}</em><div><b>${esc(a.title)}</b><span>${esc(a.why)}</span></div>${forPrint ? '' : `<button class="btn sm" data-nav="${a.nav}">Open</button>`}</div>`).join('') || '<div class="empty" style="padding:12px 0">Nothing urgent. Every unit is within its goal line and nothing is waiting.</div>'}</div>
  </div>`;
}

/* ---------- business-unit page ---------- */
const SEVCOL = { 'zero-day': 'var(--critical)', critical: 'var(--critical)', high: 'var(--serious)', medium: 'var(--warning)', low: 'var(--muted)' };
function pageUnit(id) {
  const b = S.bus.find(x => x.id === id);
  if (!b) return '<div class="card empty">Unknown business unit.</div>';
  const over = b.score > b.goal_line, max = Math.max(b.score, b.goal_line) * 1.3 || 1, mock = S.provider === 'mock';
  const servers = S.servers.filter(s => s.bu === id);
  const open = S.vulns.filter(v => v.bu === id && v.status === 'open').sort((x, y) => y.risk - x.risk);
  const tickets = S.tickets.filter(t => t.bu === id && t.status !== 'closed');
  const issues = S.issues.filter(i => i.bu === id && (i.status === 'open' || i.status === 'pending_approval'));
  const bySev = SEVS.map(s => [s, open.filter(v => v.severity === s)]).filter(x => x[1].length);
  return `
  <div class="row"><button class="btn sm" data-nav="overview">← All business units</button></div>
  <div class="grid g21">
    <div class="card"><div class="head"><div><h2>${esc(b.name)}</h2><div class="hint">Head: ${esc(b.head)}. Goal line set by leadership: ${b.goal_line}.</div></div><div class="grow"></div>${chip(over ? 'Above goal' : 'Within goal', over ? 'bad' : 'ok')}</div>
      <div class="bu"><div class="score"><b>${fmt(b.score)}</b><span>risk score, ${over ? fmt(b.score - b.goal_line) + ' over the goal line' : fmt(b.goal_line - b.score) + ' of headroom'}</span></div>
      <div class="gauge"><div class="fill ${over ? 'over' : ''}" style="width:${Math.min(100, b.score / max * 100)}%"></div><div class="goal" data-l="goal ${b.goal_line}" style="left:${b.goal_line / max * 100}%"></div></div></div>
      <h2 style="margin-top:18px">Where the risk comes from</h2>
      ${b.score ? hbar('By cause', [{ n: b.vuln_score, color: 'var(--series)', tip: `Vulnerabilities: ${fmt(b.vuln_score)}` }, { n: b.config_score, color: 'var(--before)', tip: `Configuration issues: ${fmt(b.config_score)}` }], `${fmt(b.vuln_score)} vulns, ${fmt(b.config_score)} config`) : '<div class="hint">No open risk.</div>'}
      ${bySev.length ? hbar('By severity', bySev.map(([s, l]) => ({ n: l.reduce((a, v) => a + v.risk, 0), color: SEVCOL[s], tip: `${s}: ${l.length} open, risk ${fmt(l.reduce((a, v) => a + v.risk, 0))}` })), bySev.map(([s, l]) => `${l.length} ${s}`).join(', ')) : ''}
      <div class="legend" style="margin-top:6px"><span><i style="background:var(--series)"></i>Vulnerabilities</span><span><i style="background:var(--before)"></i>Configuration</span>${bySev.map(([s]) => `<span><i style="background:${SEVCOL[s]}"></i>${s}</span>`).join('')}</div>
    </div>
    <div class="card"><h2>Downtime window</h2><div class="hint">Every ${b.window.weekday} ${p2(b.window.start_hour)}:00 UTC for ${b.window.duration_hours} hours</div>
      <div class="prose"><p>${b.held ? `On hold: “${esc(b.held)}”` : b.window_open ? 'The window is open now.' : `Next opens <b>${fday(b.next_start)}</b>.`}</p>
      <p>${b.queue.length ? 'Waiting to be patched: ' + b.queue.map(q => `<b>${esc(q.server)}</b> (${q.tickets} tickets)`).join(', ') + '.' : 'Nothing waiting to be patched.'}</p></div>
      <div class="row">${b.queue.length && !b.held ? btn(mock && !b.window_open ? 'Jump to window and patch' : 'Run window now', 'next_window', { bu: b.id }, 'sm primary') : ''}
        ${b.held ? btn('Release hold', 'release', { bu: b.id }, 'sm') : `<button class="btn sm" data-modal="hold" data-bu="${b.id}">Decline downtime</button>`}</div></div>
  </div>
  <div class="card"><div class="head"><div><h2>Risk over time</h2><div class="hint">Hover a point to see what had just happened.</div></div></div>${lineChart(b.history, b.goal_line)}</div>
  <div class="card"><h2>Servers (${servers.length})</h2><div class="tw"><table><thead><tr><th>Server</th><th>Owner</th><th>Exposure</th><th class="n">Open</th><th>Worst</th><th class="n">Risk</th><th>Last patch</th><th></th></tr></thead><tbody>
    ${servers.map(s => `<tr><td><b>${esc(s.name)}</b><div class="s mono">${esc(s.id)}</div></td><td>${esc(s.owner)}</td><td class="nw">${s.internet_facing ? chip('Internet-facing', 'wait') : '<span class="s">Internal</span>'} <span class="tag">${esc(s.criticality)}</span></td>
      <td class="n">${s.open_vulns}</td><td>${s.worst ? sev(s.worst) : chip('clean', 'ok')}</td><td class="n">${fmt(s.risk)}</td><td class="nw">${s.last_job ? chip(s.last_job.status.replace('_', ' '), s.last_job.status === 'success' ? 'ok' : 'bad') + ' <span class="s">' + fshort(s.last_job.at) + '</span>' : '<span class="s">never</span>'}</td>
      <td class="nw">${s.open_vulns ? btn('Patch now', 'patch_now', { server: s.id }, 'sm') : ''}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">This unit has no servers.</td></tr>'}</tbody></table></div></div>
  <div class="card"><h2>Largest contributors to risk</h2><div class="hint">The open items adding the most to this unit's score</div><div class="tw"><table><thead><tr><th>Item</th><th>On</th><th>Severity</th><th>Deadline</th><th class="n">Risk</th></tr></thead><tbody>
    ${open.slice(0, 10).map(v => `<tr><td><span class="mono">${esc(v.cve)}</span><div class="s">${esc(v.package)}</div></td><td>${esc(v.server_name)}</td><td>${sev(v.severity)}</td><td class="nw">${fshort(v.due_at)} ${due(v.due_at)}</td><td class="n">${fmt(v.risk)}</td></tr>`).join('')}
    ${issues.map(i => `<tr><td><b>${esc(i.control_id)}</b><div class="s">${esc(i.detail)}</div></td><td>${esc(i.resource_name)}</td><td>${sev(i.severity)}</td><td class="nw">${fshort(i.due_at)} ${due(i.due_at)}</td><td class="n">config</td></tr>`).join('')}
    ${open.length + issues.length ? '' : '<tr><td colspan="5" class="empty">Nothing open.</td></tr>'}</tbody></table></div></div>
  <div class="card"><h2>Open tickets (${tickets.length})</h2><div class="tw"><table><thead><tr><th>Ticket</th><th>Title</th><th>Assignee</th><th>Deadline</th><th>Status</th></tr></thead><tbody>
    ${tickets.map(t => `<tr class="click" data-ticket="${t.id}"><td class="mono nw">${t.id}</td><td>${esc(t.title)}</td><td class="nw">${esc(t.assignee)}</td><td class="nw">${fshort(t.due_at)} ${due(t.due_at)}</td><td>${chip(t.status.replace('_', ' '), t.overdue || t.status === 'reopened' ? 'bad' : 'wait')}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No open tickets.</td></tr>'}</tbody></table></div></div>`;
}

/* ---------- deadline chart (vulnerabilities page) ---------- */
function deadlineCard() {
  const open = S.vulns.filter(v => v.status === 'open');
  if (!open.length) return '';
  const B = [['Past deadline', d => d < 0, 'var(--critical)'], ['Due within 7 days', d => d >= 0 && d <= 7, 'var(--series)'], ['Due in 8 to 28 days', d => d > 7 && d <= 28, 'var(--series)'],
             ['Due in 29 to 90 days', d => d > 28 && d <= 90, 'var(--series)'], ['Later', d => d > 90, 'var(--series)']];
  const days = v => (D(v.due_at) - D(S.now)) / 864e5, max = open.length;
  return `<div class="card"><h2>Deadlines ahead</h2><div class="hint">Open vulnerabilities grouped by how soon they must be fixed</div>
    ${B.map(([label, test, color]) => { const n = open.filter(v => test(days(v))).length;
      return `<div class="hbar"><div>${label}</div><div class="track">${n ? `<div class="seg" style="flex:${n / max};background:${color}" data-tip="${n} open"></div><div style="flex:${1 - n / max}"></div>` : ''}</div><div class="r">${n}</div></div>`; }).join('')}</div>`;
}

/* ---------- printable report ---------- */
function pageReport() {
  const A = S.assessment, m = S.metrics, p = posture(), F = A.findings;
  const drifts = S.issues.filter(i => i.kind === 'drift'), d = m.drift, v = m.vulnerabilities, pt = m.patching;
  const n = x => x == null ? 'n/a' : x;
  return `
  <div class="row noprint"><button class="btn primary" onclick="window.print()">Print or save as PDF</button><span class="s" style="color:var(--muted)">Choose “Save as PDF” in the print dialog. The sidebar and buttons are left out.</span></div>
  <div class="card"><h1 style="font-size:22px">${esc(S.company)}: cloud security posture report</h1>
    <div class="hint" style="margin-top:4px">Generated ${fday(S.now)}. Data source: ${S.provider === 'mock' ? 'simulated environment' : 'live AWS account'}. Baseline: ${esc(S.mbss.source)}.</div></div>
  ${execCard(true)}
  <div class="card"><h2>Risk by business unit</h2><div class="tw"><table><thead><tr><th>Business unit</th><th>Head</th><th class="n">First measured</th><th class="n">Peak</th><th class="n">Now</th><th class="n">Goal line</th><th class="n">Open vulns</th><th class="n">Past deadline</th><th>Status</th></tr></thead><tbody>
    ${S.bus.map(b => `<tr><td><b>${esc(b.name)}</b></td><td>${esc(b.head)}</td><td class="n">${b.history.length ? fmt(b.history[0].score) : '–'}</td><td class="n">${b.history.length ? fmt(Math.max(...b.history.map(h => h.score))) : '–'}</td><td class="n"><b>${fmt(b.score)}</b></td><td class="n">${b.goal_line}</td><td class="n">${b.open_vulns}</td><td class="n">${b.overdue_vulns}</td><td>${chip(b.score > b.goal_line ? 'Above goal' : 'Within goal', b.score > b.goal_line ? 'bad' : 'ok')}</td></tr>`).join('')}</tbody></table></div></div>
  <div class="card"><h2>1. Initial assessment</h2><div class="hint">${A.run_id ? `${F.length} configuration gaps and ${A.vulnerabilities.length} server vulnerabilities found on ${fdate(A.at)}` : 'Not run yet'}</div>
    ${A.by_domain.map(x => hbar(x.domain, [{ n: x.passed, color: 'var(--good)', tip: '' }, { n: x.checks - x.passed, color: 'var(--critical)', tip: '' }], `${x.checks - x.passed} of ${x.checks} failed`)).join('')}
    <div class="tw" style="margin-top:10px"><table><thead><tr><th>Severity</th><th>Control</th><th>Resource</th><th>Gap</th><th>Recommended fix</th></tr></thead><tbody>
    ${F.map(f => `<tr><td>${sev(f.severity)}</td><td><b>${esc(f.control_id)}</b> <span class="s">${esc(f.cis_ref)}</span></td><td>${esc(f.resource_name)}</td><td>${esc(f.detail)}</td><td>${esc(f.recommendation)}</td></tr>`).join('')}</tbody></table></div></div>
  <div class="card"><h2>2. Baseline and drift</h2>
    <div class="kv" style="margin-bottom:12px"><span>Baseline compliance</span><div>${p.compliance == null ? 'not implemented' : Math.round(p.compliance * 100) + '%'}</div><span>Drift events</span><div>${d.drift_events} detected, ${d.attributed} traced to a user</div>
      <span>Time to detect</span><div>${n(d.mean_time_to_detect_min)} minutes on average</div><span>Remediation</span><div>${d.auto_remediated} restored automatically, ${d.remediated_after_approval} after approval, ${d.accepted_as_exception} accepted as exceptions</div></div>
    <div class="tw"><table><thead><tr><th>Control</th><th>Resource</th><th>Changed by</th><th>Changed</th><th>Detected</th><th>Outcome</th></tr></thead><tbody>
    ${drifts.map(i => `<tr><td><b>${esc(i.control_id)}</b></td><td>${esc(i.resource_name)}</td><td>${esc(i.actor || 'unknown')}</td><td class="nw">${ftime(i.changed_at)}</td><td class="nw">${ftime(i.detected_at)}</td><td>${esc(i.status.replace('_', ' '))} (${i.remediation_mode})</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No drift recorded.</td></tr>'}</tbody></table></div>
    ${S.exceptions.length ? `<h2 style="margin-top:14px">Accepted risks</h2><div class="tw"><table><thead><tr><th>Control</th><th>Resource</th><th>Reason</th><th>Approved by</th><th>Expires</th></tr></thead><tbody>${S.exceptions.map(e => `<tr><td><b>${esc(e.control_id)}</b></td><td>${esc(e.resource_name)}</td><td>${esc(e.reason)}</td><td>${esc(e.approved_by)}</td><td class="nw">${fdate(e.expires_at)}</td></tr>`).join('')}</tbody></table></div>` : ''}</div>
  <div class="card"><h2>3. Vulnerability management</h2>
    <div class="kv" style="margin-bottom:12px"><span>Found</span><div>${v.total} (${v.fixed} fixed, ${v.open} open, ${v.open_past_deadline} past deadline)</div><span>Fixed within deadline</span><div>${n(v.fixed_within_deadline_pct)}% (${v.fixed_within_deadline} of ${v.total})</div>
      <span>Patch jobs</span><div>${pt.jobs} run, ${pt.succeeded} succeeded, ${pt.rolled_back} rolled back</div><span>Success rate</span><div>${n(pt.patch_success_rate_pct)}%, rollback rate ${n(pt.rollback_rate_pct)}%</div></div>
    <div class="tw"><table><thead><tr><th>Job</th><th>Server</th><th>How</th><th>Started</th><th>Result</th><th>Steps</th></tr></thead><tbody>
    ${S.jobs.slice().reverse().map(j => `<tr><td>#${j.id}</td><td>${esc(j.server_name)}</td><td>${j.mode}</td><td class="nw">${ftime(j.started_at)}</td><td>${esc(j.status.replace('_', ' '))}</td><td>${esc(j.detail || '')}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No patch jobs.</td></tr>'}</tbody></table></div></div>`;
}

/* ---------- wire the additions into the console ---------- */
NAV.splice(7, 0, ['report', 'Report', '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/>']);
PAGES.report = pageReport; TITLES.report = 'Posture report';

const _pageOverview = pageOverview;
pageOverview = function () {
  const html = _pageOverview();
  return html.includes('<div class="kpis">') ? html.replace('<div class="kpis">', execCard() + '<div class="kpis">') : html;
};
const _buCard = buCard;
buCard = function (b) { return _buCard(b).replace('<div class="card bu">', `<div class="card bu click" data-nav="unit:${b.id}" title="Open ${esc(b.name)}">`); };
const _pageVulns = pageVulns;
pageVulns = function () {
  const html = _pageVulns(), mark = '<div class="card"><div class="head"><div><h2>Servers</h2>';
  return html.includes(mark) ? html.replace(mark, deadlineCard() + mark) : html;
};
PAGES.overview = () => pageOverview();   // PAGES captured the originals; point it at the extended versions
PAGES.vulns = () => pageVulns();
const _shell = shell;
shell = function (body) {
  let html = _shell(body);
  const dark = document.documentElement.dataset.theme === 'dark' || (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: dark)').matches);
  html = html.replace('<div class="clock">', `<button class="btn sm" data-theme-toggle="1" title="Switch between light and dark">${dark ? 'Light mode' : 'Dark mode'}</button><div class="clock">`);
  if (S.provider === 'aws-recorded') {
    html = html.replace('Live on AWS', 'Recorded from AWS').replace('Reading and changing a real AWS account.',
      'A recording of a real run on AWS. The environment has since been removed, so the buttons cannot change anything.');
  }
  if (ui.busy) html = html.replace('<div class="content">', `<div class="busy"><i></i>Working… ${S.provider === 'mock' ? '' : 'Actions on the live AWS account take time: a scan about a minute, a patch job 5 to 10 minutes.'}</div><div class="content">`);
  return html;
};

/* search box and click-to-sort on every long table; state survives re-rendering */
const tableState = {};
function enhanceTables() {
  document.querySelectorAll('.content .tw > table').forEach((table, idx) => {
    const body = table.tBodies[0];
    if (!body || body.rows.length < 8) return;
    const key = ui.route + ':' + idx, st = tableState[key] || (tableState[key] = { q: '', col: -1, dir: 1 });
    const input = document.createElement('input');
    input.type = 'text'; input.placeholder = `Search these ${body.rows.length} rows`; input.className = 'tsearch noprint'; input.value = st.q;
    const apply = () => { const q = st.q.toLowerCase(); [...body.rows].forEach(r => { r.style.display = !q || r.textContent.toLowerCase().includes(q) ? '' : 'none'; }); };
    input.addEventListener('input', () => { st.q = input.value; apply(); });
    table.parentElement.before(input);
    const sortBy = (col, dir) => {
      const val = r => { const t = (r.cells[col] ? r.cells[col].textContent : '').trim(), num = parseFloat(t.replace(/[^0-9.\-]/g, '')); return /^[#\d.\-]/.test(t) && !isNaN(num) ? num : t.toLowerCase(); };
      [...body.rows].sort((a, b) => { const x = val(a), y = val(b); return (x > y ? 1 : x < y ? -1 : 0) * dir; }).forEach(r => body.appendChild(r));
    };
    [...table.tHead.rows[0].cells].forEach((th, col) => {
      if (!th.textContent.trim()) return;
      th.classList.add('sortable'); if (st.col === col) th.dataset.dir = st.dir > 0 ? 'up' : 'down';
      th.addEventListener('click', () => { st.dir = st.col === col ? -st.dir : 1; st.col = col; sortBy(col, st.dir); table.querySelectorAll('th').forEach(x => delete x.dataset.dir); th.dataset.dir = st.dir > 0 ? 'up' : 'down'; });
    });
    if (st.col >= 0) sortBy(st.col, st.dir);
    apply();
  });
}
const _render = render;
render = function () {
  if (S && S.bus) S.bus.forEach(b => { PAGES['unit:' + b.id] = () => pageUnit(b.id); TITLES['unit:' + b.id] = b.name; });
  _render();
  enhanceTables();
};
document.addEventListener('click', e => {
  if (!e.target.closest('[data-theme-toggle]')) return;
  const root = document.documentElement, dark = root.dataset.theme === 'dark' || (!root.dataset.theme && matchMedia('(prefers-color-scheme: dark)').matches);
  root.dataset.theme = dark ? 'light' : 'dark';
  try { localStorage.setItem('cspm-theme', root.dataset.theme); } catch (err) { /* private window: the choice just is not remembered */ }
  render();
});
try { const t = localStorage.getItem('cspm-theme'); if (t) document.documentElement.dataset.theme = t; } catch (err) { /* ignore */ }
let themeBeforePrint = null;
window.addEventListener('beforeprint', () => { themeBeforePrint = document.documentElement.dataset.theme || ''; document.documentElement.dataset.theme = 'light'; });
window.addEventListener('afterprint', () => { if (themeBeforePrint) document.documentElement.dataset.theme = themeBeforePrint; else delete document.documentElement.dataset.theme; });
