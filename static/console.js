'use strict';

const $ = (id) => document.getElementById(id);
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"/></svg>`;
const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {view:'auto', mode:'upload', jobs:[], active:new Set(), maxParallel:2, selected:null, selections:{}, filters:{}, uploadSettings:{}, cryptoMode:'text', filter:'all', capabilities:[]};
const terminalStates = new Set(['done','error','cancelled']);
let toastTimer;
let saveTimer = 0;
const sessionKey = 'ctf-auto-workspace-v1';
function saveSession() {
  try {
    const jobs = state.jobs.map(({file,text,...job})=>job);
    sessionStorage.setItem(sessionKey,JSON.stringify({jobs,selections:state.selections,filters:state.filters,uploadSettings:state.uploadSettings,cryptoMode:state.cryptoMode}));
    $('session-save').textContent = 'SESSION SAVED IN THIS TAB';
  } catch { $('session-save').textContent = 'EXPORT JSON TO SAVE THIS SESSION'; }
}
function scheduleSave() {if (!saveTimer) saveTimer = setTimeout(()=>{saveTimer=0;saveSession();},300);}
function restoreSession() {
  try {
    const saved = JSON.parse(sessionStorage.getItem(sessionKey) || 'null');
    if (!Array.isArray(saved?.jobs)) return;
    state.jobs = saved.jobs.filter(job => /^[a-zA-Z0-9-]{1,80}$/.test(job.id) && categories[job.category] && ['artifact','text','web'].includes(job.kind) && Array.isArray(job.results)).slice(-256);
    state.selections = saved.selections || {}; state.filters = saved.filters || {};
    state.uploadSettings = saved.uploadSettings || {}; state.cryptoMode = saved.cryptoMode === 'upload' ? 'upload' : 'text';
    for (const job of state.jobs) {
      if (terminalStates.has(job.status)) continue;
      if (/^[a-f0-9]{12}$/.test(job.serverId || '')) {job.status='running';state.active.add(job.id);job.retry=0;}
      else {job.status='error';job.error='This input was not submitted before reload. Add it again to run.';}
    }
    for (const job of state.jobs.filter(job=>state.active.has(job.id))) poll(job);
  } catch { $('session-save').textContent = 'SESSION COULD NOT BE RESTORED'; }
}
window.addEventListener('pagehide',saveSession);

function toast(message) {
  $('toast').textContent = message; $('toast').hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { $('toast').hidden = true; }, 4500);
}

function setMode(mode) {
  const allowed = state.view === 'crypto' ? ['text','upload'] : [state.view === 'web' ? 'web' : 'upload'];
  if (!allowed.includes(mode)) return;
  state.mode = mode;
  if (state.view === 'crypto') state.cryptoMode = mode;
  document.querySelectorAll('[data-mode]').forEach(button => {
    const active = button.dataset.mode === mode;
    button.classList.toggle('active', active); button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  });
  ['upload','text','web'].forEach(name => { $('mode-' + name).hidden = name !== mode; });
  $('input-kind').textContent = mode === 'upload' ? ({auto:'AUTO CLASSIFY',network:'PCAP ANALYSIS',image:'IMAGE FORENSICS'}[state.view] || 'ARTIFACT INPUT') : ({text:'CRYPTO ANALYSIS',web:'WEB RECON'}[mode] || mode.toUpperCase());
}

const categories = {
  auto: {title:'Auto CTF', lead:'HUNT THE', word:'UNKNOWN.', heading:'Let the artifact choose its path.', description:'Drop an unfamiliar artifact. Detect its real format, unpack nested files, and follow the right solver automatically.', note:'AUTO DETECTION / ARCHIVE CORRELATION', types:['CRYPTO','ARCHIVES','PCAP','IMAGES','ELF / PDF'], input:'AUTO ARTIFACT INPUT'},
  crypto: {title:'Crypto', lead:'PEEL EVERY', word:'LAYER.', heading:'One signal. Every layer exposed.', description:'A dedicated cryptography lab. Fast byte-preserving decode chains, RSA relationships, and deeper cipher analysis with traceable results.', note:'64-LAYER FAST PATH / STRUCTURED CRYPTO', types:['RSA / JSON','ENCODED TEXT','KEYS / PEM','ARCHIVES'], input:'CRYPTO INPUT'},
  web: {title:'Web', lead:'MAP THE', word:'ATTACK SURFACE.', heading:'Explore your CTF web target.', description:'Discover routes, inspect sessions, and run CTF web workflows. Set a time and request budget before launching your target.', note:'ROUTES / SESSIONS / WEB WORKFLOWS', types:[], input:'WEB TARGET'},
  network: {title:'Network', lead:'FOLLOW THE', word:'PACKETS.', heading:'Read the conversation on the wire.', description:'Upload a packet capture. Inspect protocol activity, DNS payloads and recovered data in a dedicated network workspace.', note:'PCAP / PCAPNG / PACKET EVIDENCE', types:['PCAP','PCAPNG','TCP / UDP','DNS / HTTP'], input:'PACKET CAPTURE'},
  image: {title:'Image', lead:'BEYOND THE', word:'PIXELS.', heading:'Find what the image is hiding.', description:'Inspect metadata, image structure and steganography signals. Keep visual artifacts and forensic evidence together.', note:'METADATA / LSB / QR / FILE STRUCTURE', types:['PNG','JPEG','WEBP','EXIF','LSB / QR'], input:'IMAGE ARTIFACT'}
};
function visibleJobs() {return categories[state.view] ? state.jobs.filter(job => job.category === state.view) : state.jobs;}
function setView(view) {
  if (!categories[view] && !['findings','toolbox'].includes(view)) view = 'auto';
  if (categories[state.view]) {
    state.selections[state.view] = state.selected;
    state.filters[state.view] = state.filter;
    state.uploadSettings[state.view] = {prefix:$('upload-prefix')?.value || '',deep:!!$('upload-deep')?.checked};
  }
  state.view = view;
  state.filter = ['all','verified','candidate','decode'].includes(state.filters[view]) ? state.filters[view] : 'all';
  document.querySelectorAll('[data-filter]').forEach(button=>{const selected=button.dataset.filter===state.filter;button.classList.toggle('active',selected);button.setAttribute('aria-pressed',String(selected));});
  if ($('finding-search')) $('finding-search').value = '';
  const config = categories[view];
  document.querySelectorAll('[data-view]').forEach(button => {
    button.classList.toggle('active', button.dataset.view === view);
    if (button.dataset.view === view) button.setAttribute('aria-current','page'); else button.removeAttribute('aria-current');
  });
  $('breadcrumb-title').textContent = (config?.title || (view === 'findings' ? 'All findings' : 'Tool arsenal')).toUpperCase();
  $('workspace').hidden = !config; $('hero').hidden = !config;
  $('toolbox').hidden = view !== 'toolbox'; $('evidence-section').hidden = view === 'toolbox';
  if (config) {
    $('hero-lead').textContent = config.lead; $('hero-accent').textContent = config.word;
    $('hero-description').textContent = config.description;
    $('workspace-title').textContent = config.heading; $('workspace-note').textContent = config.note;
    $('input-title').textContent = config.input; $('queue-title').textContent = config.title.toUpperCase() + ' QUEUE';
    $('filetypes').innerHTML = config.types.map(text => `<span>${text}</span>`).join('');
    $('artifact-files').accept = view === 'network' ? '.pcap,.pcapng,.cap' : view === 'image' ? 'image/*' : '';
    $('upload-title').textContent = {auto:'Drop an artifact or challenge archive.',crypto:'Drop crypto files or an RSA bundle.',network:'Drop a PCAP or PCAPNG capture.',image:'Drop your image artifacts.'}[view] || '';
    $('mode-tabs').hidden = view !== 'crypto';
    document.querySelector('[data-mode="web"]').hidden = true;
    const upload = state.uploadSettings[view] || {};
    $('upload-prefix').value = upload.prefix || ''; $('upload-deep').checked = !!upload.deep;
    setMode(view === 'web' ? 'web' : view === 'crypto' ? state.cryptoMode : 'upload');
    state.selected = state.selections[view] || visibleJobs().at(-1)?.id || null;
  } else state.selected = null;
  renderQueue(); renderEvidence(); closeMenu();
  if (location.hash !== '#' + view) history.pushState(null,'','#'+view);
}
window.addEventListener('popstate',()=>setView(location.hash.slice(1) || 'auto'));

function closeMenu() {
  const wasOpen = $('sidebar').classList.contains('open');
  $('sidebar').classList.remove('open'); $('sidebar-scrim').classList.remove('open');
  $('menu-toggle').setAttribute('aria-expanded','false');
  syncNavigation();
  if (wasOpen) $('menu-toggle').focus();
}

const mobileNavigation = matchMedia('(max-width:760px)');
function syncNavigation() { $('sidebar').inert = mobileNavigation.matches && !$('sidebar').classList.contains('open'); }
mobileNavigation.addEventListener('change',syncNavigation);
const reducedMotion = matchMedia('(prefers-reduced-motion:reduce)');
let tiltFrame = 0;
$('hero').addEventListener('pointermove',event => {
  if (reducedMotion.matches || document.body.classList.contains('motion-paused') || event.pointerType === 'touch') return;
  const bounds = $('hero').getBoundingClientRect();
  const x = (event.clientX - bounds.left) / bounds.width - .5;
  const y = (event.clientY - bounds.top) / bounds.height - .5;
  cancelAnimationFrame(tiltFrame);
  tiltFrame = requestAnimationFrame(() => {
    $('hero').style.setProperty('--tilt-x', `${-y * 12}deg`);
    $('hero').style.setProperty('--tilt-y', `${x * 18}deg`);
  });
});
$('hero').addEventListener('pointerleave',() => {
  cancelAnimationFrame(tiltFrame);
  $('hero').style.setProperty('--tilt-x','0deg'); $('hero').style.setProperty('--tilt-y','0deg');
});

function classify(row) {
  if (row.type === 'flag' && row.status === 'verified') return 'verified';
  if (row.type === 'candidate' || row.type === 'flag') return 'candidate';
  return 'decode';
}

function allFindings() {
  return state.jobs.flatMap(job => (job.results || []).filter(row => ['flag','candidate','decode'].includes(row.type)).map(row => ({...row, mission:job.name})));
}

function renderMetrics() {
  const jobs = visibleJobs();
  const waiting = jobs.filter(job => job.status === 'queued').length;
  const flags = new Set(jobs.flatMap(job=>job.results).filter(row => classify(row) === 'verified').map(row => row.flag));
  $('metric-queue').textContent = String(waiting).padStart(2,'0');
  $('metric-active').textContent = String(jobs.filter(job=>state.active.has(job.id)).length).padStart(2,'0');
  $('metric-flags').textContent = String(flags.size).padStart(2,'0');
  $('metric-done').textContent = String(jobs.filter(job => terminalStates.has(job.status)).length).padStart(2,'0');
  $('nav-findings').textContent = String(new Set(allFindings().filter(row=>classify(row)==='verified').map(row=>row.flag)).size).padStart(2,'0');
  $('queue-badge').textContent = jobs.length;
  $('queue-progress').classList.toggle('running', jobs.some(job=>state.active.has(job.id)));
  $('queue-footer-text').textContent = jobs.some(job=>state.active.has(job.id)) ? 'ANALYZING · EARLY EVIDENCE RETAINED' : waiting ? `${waiting} CHALLENGES WAITING` : jobs.length ? 'ALL MISSIONS PROCESSED' : 'AWAITING YOUR FIRST CHALLENGE';
  $('clear-queue').disabled = waiting === 0;
}

function renderQueue() {
  scheduleSave();
  renderMetrics();
  const jobs = visibleJobs();
  if (!jobs.length) {
    $('queue-list').innerHTML = `<div class="empty-queue">${icon('layers')}<h3>The field is clear.</h3><p>Add your first challenge. Every mission and its results will appear here.</p></div>`;
    return;
  }
  const focused = document.activeElement?.closest('[data-job]')?.dataset.job;
  $('queue-list').innerHTML = jobs.map(job => {
    const running = ['running','uploading','stopping'].includes(job.status);
    const label = {queued:'QUEUED',uploading:'LOADING',running:'RUNNING',stopping:'STOPPING',done:'COMPLETE',error:'PARTIAL / ERROR',cancelled:'STOPPED'}[job.status] || job.status;
    const flags = (job.results || []).filter(row => classify(row) === 'verified').length;
    const detail = job.status === 'queued' ? 'Waiting for analysis' : `${job.elapsed || 0}s · ${flags} verified`;
    return `<button class="job${state.selected === job.id ? ' selected' : ''}" data-job="${job.id}" aria-label="View ${escapeHTML(job.name)}, ${escapeHTML(label)}"><span class="job-icon">${icon(job.kind === 'web' ? 'globe' : job.kind === 'text' ? 'key' : 'file')}</span><span><span class="job-name">${escapeHTML(job.name)}</span><span class="job-meta">${escapeHTML(detail)}</span></span><span class="job-state ${running ? 'running' : job.status}">${running ? '<span class="spinner"></span>' : ''}${label}</span></button>`;
  }).join('');
  if (focused) [...$('queue-list').querySelectorAll('[data-job]')].find(el=>el.dataset.job===focused)?.focus({preventScroll:true});
}

function makeJob(data) {
  // LAN HTTP does not expose randomUUID; these IDs only identify UI rows.
  const id = globalThis.crypto?.randomUUID?.() || `mission-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return {id, status:'queued', results:[], elapsed:0, created:new Date().toISOString(), error:null, ...data};
}

function addFiles(files) {
  let count = 0, skipped = 0;
  for (const file of files) {
    if (state.jobs.filter(j => j.status === 'queued').length >= 32 || file.size > 16 * 1024 * 1024 || !file.size) { skipped++; continue; }
    state.jobs.push(makeJob({kind:'artifact',category:categories[state.view] ? state.view : 'auto',deep:$('upload-deep').checked,name:file.name,file,size:file.size,prefix:$('upload-prefix').value.trim()}));
    count++;
  }
  if (skipped) toast(`${skipped} file(s) skipped. Maximum: 32 waiting files, 16 MiB each; empty files are not analyzed.`);
  else if (count) toast(`${count} challenge${count === 1 ? '' : 's'} queued. Let the hunt begin.`);
  renderQueue(); pump();
}

function queueText(event) {
  event.preventDefault();
  const text = $('crypto-text').value.trim();
  if (!text) return;
  if (new TextEncoder().encode(text).length > 256 * 1024) { toast('For text above 256 KiB, use an artifact file.'); return; }
  if (!queueHasSpace()) return;
  state.jobs.push(makeJob({kind:'text',category:'crypto',deep:$('crypto-deep').checked,name:'Crypto signal ' + (state.jobs.filter(j => j.kind === 'text').length + 1),text,prefix:$('crypto-prefix').value.trim()}));
  renderQueue(); pump();
}

function queueWeb(event) {
  event.preventDefault();
  let url;
  try { url = new URL($('web-url').value.trim()); } catch { toast('Enter a complete http:// or https:// challenge URL.'); return; }
  if (!['http:','https:'].includes(url.protocol)) { toast('Web targets must use HTTP or HTTPS.'); return; }
  if (!queueHasSpace()) return;
  state.jobs.push(makeJob({kind:'web',category:'web',stop_on_flag:$('web-stop-flag').checked,name:url.host,url:url.href,prefix:$('web-prefix').value.trim(),browser:$('web-browser').checked,deep:$('web-deep').checked,max_seconds:Number($('web-seconds').value),max_requests:Number($('web-requests').value)}));
  renderQueue(); pump();
}

function queueHasSpace() {
  if (state.jobs.filter(j => j.status === 'queued').length >= 32) { toast('The queue holds 32 waiting challenges.'); return false; }
  return true;
}

async function responseJSON(response) {
  const data = await response.json();
  if (!response.ok) {const error=new Error(data.error || `HTTP ${response.status}`);error.status=response.status;throw error;}
  return data;
}

function pump() {
  while (state.active.size < state.maxParallel) {
    const job = state.jobs.find(item => item.status === 'queued');
    if (!job) break;
    startJob(job);
  }
  renderQueue();
}
async function startJob(job) {
  state.active.add(job.id); job.retry = 0;
  if (!state.selected && state.view === job.category) state.selected = job.id;
  job.status = 'uploading'; renderQueue(); renderEvidence();
  try {
    let data;
    if (job.kind === 'artifact') {
      const body = new FormData(); body.append('file',job.file); body.append('prefix',job.prefix);
      body.append('category',job.category); body.append('deep',job.deep ? '1' : '0');
      data = await responseJSON(await fetch('/api/upload?competition=1',{method:'POST',body}));
      delete job.file;
    } else {
      const body = job.kind === 'web' ? {category:'web',url:job.url,prefix:job.prefix,browser:job.browser,deep:job.deep,max_seconds:job.max_seconds,max_requests:job.max_requests,stop_on_flag:job.stop_on_flag} : {category:'crypto',text:job.text,prefix:job.prefix,competition:true,deep:job.deep};
      data = await responseJSON(await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}));
      delete job.text;
    }
    if (!data.job_id) throw new Error('Server did not return a job ID.');
    job.serverId = data.job_id; job.status = 'running'; renderQueue(); renderEvidence(); poll(job);
  } catch (error) {
    job.status = 'error'; job.error = String(error.message || error); delete job.file; delete job.text;
    state.active.delete(job.id); renderQueue(); renderEvidence(); pump();
  }
}

async function poll(job) {
  if (!state.active.has(job.id)) return;
  try {
    const data = await responseJSON(await fetch('/api/status/' + encodeURIComponent(job.serverId)));
    if (!state.active.has(job.id)) return;
    job.retry = 0; job.connectionError = null;
    job.status = data.status; job.results = data.results || []; job.error = data.error; job.elapsed = data.elapsed;
    renderQueue(); renderEvidence();
    if (terminalStates.has(job.status)) {
      state.active.delete(job.id); job.finished = new Date().toISOString(); renderQueue(); renderEvidence();
      pump(); return;
    }
  } catch (error) {
    if (error.status === 404) {
      job.status='error'; job.error='The server no longer has this job. Recovered evidence is retained; add the challenge again to rerun.';
      state.active.delete(job.id);renderQueue();renderEvidence();pump();return;
    }
    job.connectionError = 'Connection interrupted. Retrying without discarding the job.';
    job.retry++; renderEvidence();
  }
  setTimeout(() => poll(job), Math.min(5000, 500 + job.retry * 500));
}

async function stopJob() {
  const job = state.jobs.find(item => item.id === state.selected && state.active.has(item.id));
  if (!job || !job.serverId || job.status === 'stopping') return;
  job.status = 'stopping'; renderQueue(); renderEvidence();
  try {
    const data = await responseJSON(await fetch('/api/stop/' + encodeURIComponent(job.serverId),{method:'POST'}));
    if (!data.accepted && !terminalStates.has(data.status) && data.status !== 'stopping') throw new Error('Stop not accepted');
    toast('Stop requested. Partial evidence will be retained.');
  } catch (error) {
    job.status = 'running'; toast('Could not stop this job. Try again.'); renderQueue(); renderEvidence();
  }
}

function readableValue(row) {
  return row.flag ?? row.value ?? row.output ?? row.data ?? row.path ?? row.url ?? JSON.stringify(row);
}

function evidenceDetails(row) {
  const evidence = Array.isArray(row.evidence) ? row.evidence : [];
  const solution = row.solution || row.explanation;
  const steps = solution?.steps || [];
  if (!evidence.length && !solution) return '';
  return `<details><summary>Inspect evidence${steps.length ? ' · ' + steps.length + ' steps' : ''}</summary>${solution?.summary ? `<p class="finding-source">${escapeHTML(solution.summary)}</p>` : ''}${evidence.length ? `<ul>${evidence.map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul>` : ''}${steps.map((step,index) => `<div class="trace-step">${index+1}. ${escapeHTML(step.operation || 'Decode')}<code>IN: ${escapeHTML(step.input)}</code><code>OUT: ${escapeHTML(step.output)}</code></div>`).join('')}</details>`;
}

function decodePath(row) {
  const path = String(row.source || row.method || '').split(':').at(-1).split('>');
  const operations = new Set(['base64','base32','hex','binary','base85','ascii85','url','html','json-string','compressed','gzip','zlib','unicode','rot13']);
  if (!path.length || path.length > 64 || !path.every(step=>operations.has(step))) return '';
  const groups = [];
  for (const step of path) {if (groups.at(-1)?.step === step) groups.at(-1).count++; else groups.push({step,count:1});}
  return `<ol class="decode-path" aria-label="Recovered decode path">${groups.map(group=>`<li>${escapeHTML(group.step)}${group.count>1 ? ` × ${group.count}` : ''}</li>`).join('')}<li class="path-result">plaintext</li></ol>`;
}

let displayedRows = [];
let evidenceRenderKey = '';
function renderEvidence() {
  const job = state.jobs.find(item => item.id === state.selected);
  const showAll = state.view === 'findings';
  $('evidence-meta').hidden = !job && !showAll;
  $('selected-name').textContent = showAll ? 'All missions in this session' : job?.name || '';
  $('selected-status').textContent = job ? `${job.status.toUpperCase()} · ${job.elapsed || 0}s` : '';
  $('stop-job').hidden = !job || !state.active.has(job.id) || !job.serverId;
  $('stop-job').disabled = job?.status === 'stopping';
  let rows = showAll ? allFindings() : job?.results || [];
  rows = rows.filter(row => !['auto','file','text-input'].includes(row.type));
  const query = $('finding-search').value.trim().toLowerCase();
  if (query) rows = rows.filter(row => JSON.stringify(row).toLowerCase().includes(query));
  if (state.filter !== 'all') rows = rows.filter(row => classify(row) === state.filter);
  rows = [...rows].sort((a,b) => ({verified:0,candidate:1,decode:2}[classify(a)] - {verified:0,candidate:1,decode:2}[classify(b)]));
  const limited = rows.length > 300; displayedRows = rows.slice(0,300);
  const notice = !showAll && (job?.error || job?.connectionError) ? `<div class="notice">${escapeHTML(job.error || job.connectionError)}</div>` : '';
  const renderKey = JSON.stringify([state.selected, showAll, state.filter, job?.status, notice, limited, displayedRows]);
  if (renderKey === evidenceRenderKey) return;
  evidenceRenderKey = renderKey;
  if (!displayedRows.length) {
    const running = job && ['uploading','running','stopping'].includes(job.status);
    const title = running ? 'Following the signal…' : job || showAll ? 'No matching evidence yet.' : 'Good answers leave a trail.';
    const detail = running ? 'The analysis is running. Early findings appear here as they are recovered.' : job ? 'Try another filter, provide more context, or use the CLI for a deeper run.' : 'Recovered flags, candidate matches and decode steps will appear here. Select a mission to inspect its results.';
    $('findings').innerHTML = notice + `<div class="evidence-empty">${icon('scan')}<div><h3>${title}</h3><p>${detail}</p></div></div>`;
    return;
  }
  // Preserve expanded evidence while live polling updates other findings.
  const expanded = new Set(Array.from($('findings').querySelectorAll('details[open]')).map(el => el.closest('[data-evidence-key]')?.dataset.evidenceKey));
  $('findings').innerHTML = notice + displayedRows.map((row,index) => {
    const kind = classify(row);
    const value = readableValue(row);
    const label = kind === 'verified' ? 'VERIFIED · LOCAL EVIDENCE' : kind === 'candidate' ? 'CANDIDATE · NEEDS VERIFICATION' : (row.method || row.section || 'DECODE').toString().slice(0,90);
    const key = String(row.source || row.method || '') + ':' + String(value).slice(0,150);
    return `<article class="finding${kind === 'verified' ? ' flag' : ''}" data-evidence-key="${escapeHTML(key)}"><div class="finding-head"><span class="badge ${kind}">${icon(kind === 'verified' ? 'flag' : kind === 'candidate' ? 'scan' : 'brackets')}${escapeHTML(label)}</span><button class="quiet-button" data-copy="${index}" aria-label="Copy finding">${icon('copy')}Copy</button></div>${decodePath(row)}<pre class="finding-value">${escapeHTML(typeof value === 'object' ? JSON.stringify(value,null,2) : value)}</pre>${row.source || row.mission ? `<p class="finding-source">${escapeHTML(row.mission || '')}${row.mission && row.source ? ' / ' : ''}${escapeHTML(row.source || '')}</p>` : ''}${evidenceDetails(row)}</article>`;
  }).join('') + (limited ? '<p class="small-note">Showing the first 300 findings. Export JSON for the complete results.</p>' : '');
  $('findings').querySelectorAll('[data-evidence-key]').forEach(article => {
    if (expanded.has(article.dataset.evidenceKey) && article.querySelector('details')) article.querySelector('details').open = true;
  });
}

async function copyFinding(index) {
  const row = displayedRows[index]; if (!row) return;
  const value = readableValue(row); const text = typeof value === 'object' ? JSON.stringify(value,null,2) : String(value);
  try { await navigator.clipboard.writeText(text); toast('Finding copied.'); }
  catch { toast('Clipboard unavailable. Select and copy the result text.'); }
}

function exportResults() {
  const jobs = state.jobs.map(({file,text,...job}) => job);
  const blob = new Blob([JSON.stringify({schema_version:1,exported:new Date().toISOString(),verification:'Local evidence; no scoreboard submissions',jobs},null,2)],{type:'application/json'});
  const url = URL.createObjectURL(blob); const link = document.createElement('a');
  link.href = url; link.download = 'ctf-auto-session.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url),1000);
}

async function loadCapabilities() {
  try {
    const data = await responseJSON(await fetch('/api/capabilities'));
    state.capabilities = data.capabilities || [];
    state.maxParallel = Math.max(1,Math.min(4,data.runtime?.parallel_jobs || 2));
    $('runtime-profile').textContent = `${data.runtime?.logical_cpus || '?'} CPU THREADS / ${state.maxParallel} PARALLEL JOBS / 64-LAYER FAST PATH`;
    pump();
    $('engine-dot').classList.add('online'); $('engine-status').textContent = 'ENGINE CONNECTED';
    $('tool-grid').innerHTML = state.capabilities.map(tool => `<article class="tool-card"><div class="tool-card-head"><span>${escapeHTML(tool.name)}</span><span class="tool-state${tool.available ? ' ready' : ''}">${tool.available ? 'DETECTED' : 'OPTIONAL'}</span></div><p>${escapeHTML(tool.detail)}</p></article>`).join('');
  } catch {
    $('engine-dot').classList.remove('online'); $('engine-status').textContent = 'ENGINE UNREACHABLE';
    $('tool-grid').innerHTML = '<div class="notice">Could not check capabilities. Start the server with ./ctf webui and reload.</div>';
  }
}

document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click',() => setView(button.dataset.view)));
document.querySelectorAll('[data-mode]').forEach(button => {
  button.addEventListener('click',() => setMode(button.dataset.mode));
  button.addEventListener('keydown',event => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    const tabs = [...document.querySelectorAll('[data-mode]')].filter(tab=>!tab.hidden); const index = tabs.indexOf(button);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length-1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    setMode(tabs[next].dataset.mode); tabs[next].focus();
  });
});
document.querySelectorAll('[data-filter]').forEach(button => button.addEventListener('click',() => {
  state.filter = button.dataset.filter;
  document.querySelectorAll('[data-filter]').forEach(item => {item.classList.toggle('active',item === button);item.setAttribute('aria-pressed',String(item === button));});
  renderEvidence();
}));
$('browse-button').addEventListener('click',() => $('artifact-files').click());
$('upload-zone').addEventListener('click',() => $('artifact-files').click());
$('upload-zone').addEventListener('keydown',event => {if (['Enter',' '].includes(event.key)) {event.preventDefault();$('artifact-files').click();}});
$('artifact-files').addEventListener('change',event => {addFiles(event.target.files);event.target.value = '';});
['dragenter','dragover'].forEach(type => $('upload-zone').addEventListener(type,event => {event.preventDefault();$('upload-zone').classList.add('dragging');}));
['dragleave','drop'].forEach(type => $('upload-zone').addEventListener(type,event => {event.preventDefault();$('upload-zone').classList.remove('dragging');}));
$('upload-zone').addEventListener('drop',event => addFiles(event.dataTransfer.files));
$('mode-text').addEventListener('submit',queueText); $('mode-web').addEventListener('submit',queueWeb);
$('queue-list').addEventListener('click',event => {const button = event.target.closest('[data-job]');if (!button) return;state.selected = button.dataset.job;const job = state.jobs.find(item=>item.id === button.dataset.job);if(job && state.view !== job.category) setView(job.category);state.selected = button.dataset.job;renderQueue();renderEvidence();});
$('clear-queue').addEventListener('click',() => {state.jobs = state.jobs.filter(job => job.status !== 'queued' || job.category !== state.view);renderQueue();renderEvidence();toast('Waiting challenges cleared.');});
$('findings').addEventListener('click',event => {const button = event.target.closest('[data-copy]');if (button) copyFinding(Number(button.dataset.copy));});
$('download-results').addEventListener('click',exportResults); $('stop-job').addEventListener('click',stopJob);
$('finding-search').addEventListener('input',renderEvidence);
$('menu-toggle').addEventListener('click',() => {const open = !$('sidebar').classList.contains('open');$('sidebar').classList.toggle('open',open);$('sidebar-scrim').classList.toggle('open',open);$('menu-toggle').setAttribute('aria-expanded',String(open));syncNavigation();if (open) $('sidebar').querySelector('.nav-button.active').focus();});
$('sidebar-scrim').addEventListener('click',closeMenu);
document.addEventListener('keydown',event => {if (event.key === 'Escape') closeMenu();if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {const form = $(state.mode === 'web' ? 'mode-web' : 'mode-text');if (!form.hidden) form.requestSubmit();}});
function setMotion(paused) {document.body.classList.toggle('motion-paused',paused);$('motion-toggle').setAttribute('aria-pressed',String(paused));$('motion-toggle').setAttribute('aria-label',paused ? 'Resume decorative animation' : 'Pause decorative animation');}
try {setMotion(localStorage.getItem('ctf-auto-motion') === 'paused');} catch {}
$('motion-toggle').addEventListener('click',() => {const paused = !document.body.classList.contains('motion-paused');setMotion(paused);try {localStorage.setItem('ctf-auto-motion',paused ? 'paused' : 'enabled');} catch {}});
function clockTick() {$('clock').textContent = new Intl.DateTimeFormat('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'}).format(new Date());$('clock').dateTime = new Date().toISOString();}
clockTick();setInterval(clockTick,1000);restoreSession();setView(location.hash.slice(1) || 'auto');loadCapabilities();syncNavigation();
