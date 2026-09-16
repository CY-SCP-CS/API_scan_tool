const $ = (selector) => document.querySelector(selector);
let activeJob = null;
let activeFindings = [];
let healthInfo = null;
const progress = {queued: 5, semgrep: 30, ai_review: 60, validation: 82, report: 95, completed: 100, failed: 100};

function lines(value) { return value.split(/\r?\n/).map((x) => x.trim()).filter(Boolean); }
function headers(value) { return Object.fromEntries(lines(value).map((line) => { const i = line.indexOf(':'); return i > 0 ? [line.slice(0, i).trim(), line.slice(i + 1).trim()] : null; }).filter(Boolean)); }
function escape(text) { const el = document.createElement('span'); el.textContent = text ?? ''; return el.innerHTML; }
function selectedProvider() { return document.querySelector('input[name="ai_provider"]:checked').value; }
function setBurpFields() { const enabled = $('#use-burp').checked; $('#burp-settings').querySelectorAll('input').forEach((input) => { input.disabled = !enabled; }); }
function setHealth() {
  if (!healthInfo) return;
  const provider = selectedProvider();
  const present = provider === 'deepseek' ? healthInfo.has_deepseek_api_key : healthInfo.has_openai_api_key;
  $('#health').textContent = present ? `${provider === 'deepseek' ? 'DeepSeek' : 'OpenAI'} Key 已配置` : `请在 .env 配置 ${provider === 'deepseek' ? 'DEEPSEEK_API_KEY' : 'OPENAI_API_KEY'}`;
}
function setProvider() {
  const provider = selectedProvider();
  document.querySelectorAll('[data-models-for]').forEach((group) => {
    const active = group.dataset.modelsFor === provider;
    group.hidden = !active;
    group.querySelectorAll('input').forEach((input) => { input.disabled = !active; });
    if (active && !group.querySelector('input:checked')) group.querySelector('input').checked = true;
  });
  setHealth();
}
function renderFindings() {
  const severity = $('#severity-filter').value;
  const status = $('#status-filter').value;
  $('#findings').innerHTML = activeFindings.filter((f) => (!severity || f.severity === severity) && (!status || f.validation?.status === status)).map((f) => `<tr data-id="${f.id}"><td>${escape(f.severity)}</td><td>${escape(f.vulnerability)}</td><td>${escape(f.path)}:${f.line}</td><td>${escape(f.ai?.summary || '—')}</td><td>${escape(f.validation?.status || '—')}</td></tr>`).join('') || '<tr><td colspan="5">没有匹配结果</td></tr>';
  document.querySelectorAll('tr[data-id]').forEach((row) => { row.onclick = () => showDetail(row.dataset.id); });
}
function showDetail(id) { const f = activeFindings.find((item) => item.id === id); if (!f) return; $('#detail').hidden = false; $('#detail').innerHTML = `<h3>${escape(f.rule_id)}</h3><p><strong>${escape(f.message)}</strong></p><p>AI：${escape(f.ai?.summary || '未完成')}<br>修复：${escape(f.ai?.recommended_fix || '—')}<br>验证：${escape(f.validation?.reason || '—')}</p><pre>${escape(f.context || '')}</pre>`; }
function setEvent(event) { $('#status').textContent = event.stage; $('#progress-bar').style.width = `${progress[event.stage] ?? 10}%`; const item = document.createElement('li'); item.textContent = `[${event.stage}] ${event.message}`; $('#events').append(item); $('#events').scrollTop = $('#events').scrollHeight; }
async function loadJob() { const response = await fetch(`/api/jobs/${activeJob}`); const job = await response.json(); activeFindings = job.findings; $('#finding-section').hidden = false; renderFindings(); if (job.error) $('#task-error').textContent = job.error; if (job.status === 'completed' || job.status === 'failed') { ['json', 'html', 'sarif'].forEach((kind) => { $(`#${kind}-report`).href = `/api/jobs/${activeJob}/reports/${kind}`; }); $('#reports').hidden = false; } }
function streamJob(id) { const source = new EventSource(`/api/jobs/${id}/events`); source.onmessage = (event) => setEvent(JSON.parse(event.data)); source.addEventListener('done', async () => { source.close(); await loadJob(); await loadHistory(); }); source.onerror = () => { source.close(); loadJob(); }; }
async function loadHistory() { try { const jobs = await (await fetch('/api/jobs')).json(); $('#history').innerHTML = jobs.map((job) => `<tr><td>${escape(job.id)}</td><td>${escape(job.status)}</td><td>${escape(job.config.source_path)}</td><td>${job.report_paths.html ? `<a href="/api/jobs/${job.id}/reports/html">HTML</a> · <a href="/api/jobs/${job.id}/reports/sarif">SARIF</a>` : '—'}</td></tr>`).join('') || '<tr><td colspan="4">没有已保存的任务</td></tr>'; } catch (_) { $('#history').innerHTML = '<tr><td colspan="4">无法读取历史任务</td></tr>'; } }

$('#scan-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('#form-error').textContent = ''; $('#events').innerHTML = ''; $('#task-error').textContent = '';
  const form = new FormData(event.currentTarget); const payload = Object.fromEntries(form.entries());
  payload.languages = [...document.querySelectorAll('input[name="languages"]:checked')].map((input) => input.value); payload.allowlist = lines(form.get('allowlist') || ''); payload.headers = headers(form.get('headers') || ''); payload.confirm_authorized = form.get('confirm_authorized') === 'on'; payload.use_burp = form.get('use_burp') === 'on';
  ['rate_limit_per_minute', 'max_requests_per_finding'].forEach((key) => { payload[key] = Number(payload[key]); }); if (payload.use_burp) payload.burp_port = Number(payload.burp_port);
  try { const response = await fetch('/api/jobs', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)}); const body = await response.json(); if (!response.ok) throw new Error(body.detail || '无法创建任务'); activeJob = body.id; $('#task-section').hidden = false; $('#task-id').textContent = `任务 ID：${activeJob}`; setEvent({stage: 'queued', message: '任务已加入队列'}); streamJob(activeJob); } catch (error) { $('#form-error').textContent = error.message; }
});
$('#severity-filter').onchange = renderFindings; $('#status-filter').onchange = renderFindings; $('#use-burp').onchange = setBurpFields; document.querySelectorAll('input[name="ai_provider"]').forEach((input) => { input.onchange = setProvider; });
setBurpFields(); setProvider();
fetch('/api/health').then((r) => r.json()).then((data) => { healthInfo = data; setHealth(); }).catch(() => { $('#health').textContent = '服务异常'; });
loadHistory();
