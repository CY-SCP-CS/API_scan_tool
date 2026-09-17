const $ = (selector) => document.querySelector(selector);
const models = { openai: ["gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.6-sol"], deepseek: ["deepseek-flash", "deepseek-v4-pro"] };
let health = null;
let timer = null;

function setModels() {
  const provider = $('#provider').value;
  $('#model').innerHTML = models[provider].map((value, index) => `<option value="${value}" ${index === 0 ? 'selected' : ''}>${value}</option>`).join('');
  setKeyStatus();
}
function setKeyStatus() {
  if (!health) return;
  const deepseek = $('#provider').value === 'deepseek';
  const configured = deepseek ? health.has_deepseek_api_key : health.has_openai_api_key;
  $('#key-status').textContent = configured ? `${deepseek ? 'DeepSeek' : 'OpenAI'} Key 已配置` : `请配置 ${deepseek ? 'DEEPSEEK_API_KEY' : 'OPENAI_API_KEY'}`;
  $('#key-status').classList.toggle('warning', !configured);
}
function addEvent(message) { const item = document.createElement('li'); item.textContent = message; $('#events').append(item); }
async function poll(id) {
  const response = await fetch(`/api/reviews/${id}`);
  if (!response.ok) throw new Error('无法读取审查任务');
  const job = await response.json();
  $('#status').textContent = job.status; $('#events').innerHTML = ''; job.events.forEach(addEvent);
  if (job.status === 'completed') {
    clearInterval(timer); timer = null; $('#submit').disabled = false;
    $('#report-card').hidden = false; $('#report').textContent = job.report_markdown; $('#download').href = `/api/reviews/${id}/report`;
  } else if (job.status === 'failed') {
    clearInterval(timer); timer = null; $('#task-error').textContent = job.error || '审查失败'; $('#submit').disabled = false;
  }
}

$('#review-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('#form-error').textContent = ''; $('#task-error').textContent = ''; $('#events').innerHTML = ''; $('#report-card').hidden = true; $('#submit').disabled = true;
  try {
    const payload = Object.fromEntries(new FormData(event.currentTarget));
    const response = await fetch('/api/reviews', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    const body = await response.json(); if (!response.ok) throw new Error(body.detail?.[0]?.msg || body.detail || '无法创建审查任务');
    $('#progress-card').hidden = false; $('#task-id').textContent = `任务 ID：${body.id}`; $('#status').textContent = body.status;
    if (timer) clearInterval(timer); await poll(body.id); timer = setInterval(() => poll(body.id).catch((error) => { $('#task-error').textContent = error.message; }), 800);
  } catch (error) { $('#form-error').textContent = error.message; $('#submit').disabled = false; }
});

$('#provider').onchange = setModels; setModels();
fetch('/api/health').then((response) => response.json()).then((data) => { health = data; setKeyStatus(); }).catch(() => { $('#key-status').textContent = '后端服务不可用'; });
