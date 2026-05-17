/* ===== BÚNKER DE VIAJES - APP CORE v2 ===== */

/* ---------- Estado ---------- */
let currentViajeId = null;
let currentTab = 'agenda';
let masterPassword = '';
let modalConfirmFn = null;
let wakeLockObj = null;

const $ = (sel) => document.querySelector(sel);
const escHTML = (s) => (s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const escAttr = (s) => (s || '').replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"');

/* ---------- Fechas: dd/mm/aaaa ---------- */
const RE_FECHA = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/;

function parseFecha(str) {
  if (!str) return null;
  const m = str.match(RE_FECHA);
  if (!m) return null;
  const d = parseInt(m[1], 10), mo = parseInt(m[2], 10), y = parseInt(m[3], 10);
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  const date = new Date(y, mo - 1, d, 12, 0, 0);
  if (date.getFullYear() !== y || date.getMonth() !== mo - 1 || date.getDate() !== d) return null;
  return date;
}

function fmtDate(d) {
  if (!d) return '';
  const date = d instanceof Date ? d : new Date(d);
  if (isNaN(date)) return String(d);
  const day = String(date.getDate()).padStart(2, '0');
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const year = date.getFullYear();
  return `${day}/${month}/${year}`;
}

function fechaHoy() {
  const d = new Date();
  d.setHours(12,0,0,0);
  return fmtDate(d);
}

function diasRango(inicioStr, finStr) {
  const ini = parseFecha(inicioStr);
  const fin = parseFecha(finStr);
  if (!ini || !fin || ini > fin) return [];
  const res = [];
  const cur = new Date(ini);
  while (cur <= fin) {
    res.push(fmtDate(cur));
    cur.setDate(cur.getDate() + 1);
  }
  return res;
}

function diaSemana(str) {
  const d = parseFecha(str);
  if (!d) return '';
  const dias = ['Domingo','Lunes','Martes','Miércoles','Jueves','Viernes','Sábado'];
  return dias[d.getDay()];
}

function fechaHoraToISO(fechaStr, horaStr) {
  const d = parseFecha(fechaStr);
  if (!d) return null;
  const [h, m] = (horaStr || '00:00').split(':').map(Number);
  d.setHours(h || 0, m || 0, 0, 0);
  return d.toISOString();
}

function horaDesdeISO(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  return d.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
}

/* ---------- Base de datos ---------- */
const db = new Dexie('BunkerViajes');
db.version(3).stores({
  viajes: '++id, destino, fecha_inicio, fecha_fin, estado, creado',
  reservas: '++id, viaje_id, tipo, titulo, localizador, fecha',
  eventos: '++id, viaje_id, fecha_hora, tipo, titulo, [viaje_id+fecha_hora]',
  agenda_dias: '++id, viaje_id, fecha, [viaje_id+fecha]',
  puntos_interes: '++id, viaje_id, fecha, nombre, tipo',
  documentos: '++id, viaje_id, nombre, tipo, tags, fecha_caducidad, cifrado',
  archivos: '++id, doc_id, nombre, mimeType',
  adjuntos: '++id, evento_id, doc_id',
  checklists: '++id, viaje_id, categoria, texto, completado, orden',
  config: 'clave'
});

/* ---------- Config ---------- */
async function getConfig(k) { const r = await db.config.get(k); return r ? r.valor : undefined; }
async function setConfig(k, v) { await db.config.put({ clave: k, valor: v }); }

/* ---------- Criptografía ---------- */
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptBuffer(buffer, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buffer);
  return { salt: Array.from(salt), iv: Array.from(iv), data: new Uint8Array(encrypted) };
}

async function decryptBuffer(encryptedUint8, saltArr, ivArr, password) {
  const salt = new Uint8Array(saltArr);
  const iv = new Uint8Array(ivArr);
  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedUint8);
  return decrypted;
}

function ensurePassword() {
  if (!masterPassword) {
    const p = prompt('Establece una contraseña maestra para cifrar documentos:');
    if (!p) throw new Error('Contraseña requerida');
    masterPassword = p;
  }
  return masterPassword;
}

/* ---------- Claude API ---------- */
async function llamarClaude(contentBlocks, max_tokens = 1200) {
  const apiKey = await getConfig('claude_api_key');
  const model = await getConfig('claude_model') || 'claude-3-haiku-20240307';
  const proxy = await getConfig('claude_proxy');
  if (!apiKey) throw new Error('Configura tu API key de Claude primero');

  const body = {
    model,
    max_tokens,
    messages: [{ role: 'user', content: contentBlocks }]
  };

  const url = proxy || 'https://api.anthropic.com/v1/messages';
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    let errTxt = '';
    try { const e = await res.json(); errTxt = JSON.stringify(e.error || e); } catch { errTxt = await res.text(); }
    throw new Error(`Claude HTTP ${res.status}: ${errTxt}`);
  }

  const data = await res.json();
  return data.content?.[0]?.text || '';
}

function blobToBase64(blob) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onloadend = () => resolve(r.result.split(',')[1]);
    r.onerror = reject;
    r.readAsDataURL(blob);
  });
}

async function analizarDocumentoIA(docId) {
  const doc = await db.documentos.get(docId);
  const arch = await db.archivos.where({ doc_id: docId }).first();
  if (!arch) { alert('Archivo no encontrado'); return; }

  let blob = arch.blob;
  if (doc.cifrado) {
    const pw = prompt('Este documento está cifrado. Introduce contraseña maestra para analizar:');
    if (!pw) return;
    try {
      const dec = await decryptBuffer(arch.blob, arch.salt, arch.iv, pw);
      blob = new Uint8Array(dec);
    } catch (e) { alert('Contraseña incorrecta'); return; }
  }

  const base64 = await blobToBase64(new Blob([blob], { type: arch.mimeType }));
  const mediaType = arch.mimeType;

  let content = [];
  if (mediaType.startsWith('image/')) {
    content.push({ type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } });
  } else if (mediaType === 'application/pdf') {
    content.push({ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64 } });
  } else {
    alert('Solo imágenes y PDFs pueden analizarse automáticamente. Para otros archivos, copia el texto manualmente.');
    return;
  }

  content.push({
    type: 'text',
    text: 'Eres un asistente de viajes. Extrae la información clave de este documento (billete, reserva, seguro, etc) y responde ÚNICAMENTE con un objeto JSON sin markdown, con estas claves: tipo (vuelo/hotel/tren/bus/barco/actividad/seguro/otro), titulo, localizador, fecha (dd/mm/aaaa), hora (HH:MM), origen, destino, notas_adicionales. Si algún dato no aparece, usa null.'
  });

  try {
    const texto = await llamarClaude(content, 1200);
    const jsonMatch = texto.match(/\{[\s\S]*\}/);
    const datos = jsonMatch ? JSON.parse(jsonMatch[0]) : JSON.parse(texto);

    abrirModal('Resultado del análisis', `
      <label>Tipo</label><input id="ia-tipo" value="${escAttr(datos.tipo || 'otro')}">
      <label>Título</label><input id="ia-titulo" value="${escAttr(datos.titulo || doc.nombre)}">
      <label>Localizador</label><input id="ia-loc" value="${escAttr(datos.localizador || '')}">
      <label>Fecha</label><input id="ia-fecha" class="input-fecha" placeholder="dd/mm/aaaa" value="${escAttr(datos.fecha || '')}">
      <label>Hora</label><input id="ia-hora" type="time" value="${escAttr(datos.hora || '')}">
      <label>Origen</label><input id="ia-origen" value="${escAttr(datos.origen || '')}">
      <label>Destino</label><input id="ia-destino" value="${escAttr(datos.destino || '')}">
      <label>Notas</label><textarea id="ia-notas">${escHTML(datos.notas_adicionales || '')}</textarea>
      <p style="font-size:.8rem;color:var(--text-muted)">Revisa los datos antes de guardar.</p>
    `, async () => {
      const fechaStr = $('#ia-fecha').value;
      const horaStr = $('#ia-hora').value;
      const iso = fechaHoraToISO(fechaStr, horaStr);
      await db.reservas.add({
        viaje_id: currentViajeId,
        tipo: $('#ia-tipo').value || 'otros',
        titulo: $('#ia-titulo').value || 'Sin título',
        localizador: $('#ia-loc').value,
        fecha: iso,
        notas: $('#ia-notas').value
      });
      if (iso) {
        await db.eventos.add({
          viaje_id: currentViajeId,
          fecha_hora: iso,
          fecha_dia: fechaStr,
          tipo: $('#ia-tipo').value || 'otros',
          titulo: $('#ia-titulo').value || 'Sin título',
          notas: $('#ia-notas').value
        });
      }
      cerrarModalDirecto();
      await renderTab();
    });
  } catch (e) {
    alert('Error analizando: ' + e.message);
    console.error(e);
  }
}

async function resumirDiaIA(fechaStr) {
  const v = await db.viajes.get(currentViajeId);
  const eventos = await db.eventos.where({ viaje_id: currentViajeId, fecha_dia: fechaStr }).sortBy('fecha_hora');
  const pois = await db.puntos_interes.where({ viaje_id: currentViajeId, fecha: fechaStr }).toArray();
  const ag = await db.agenda_dias.where({ viaje_id: currentViajeId, fecha: fechaStr }).first();

  const promptText = [
    `Eres un asistente de viajes experto.`,
    `Viaje a ${v.destino}.`,
    `Día ${fechaStr} (${diaSemana(fechaStr)}).`,
    ag?.alojamiento ? `Alojamiento: ${ag.alojamiento}.` : 'Sin alojamiento registrado.',
    eventos.length ? `Eventos del día:\n${eventos.map(e => `- ${horaDesdeISO(e.fecha_hora)}: ${e.titulo} (${e.tipo})`).join('\n')}` : 'Sin eventos programados.',
    pois.length ? `Lugares ya planeados:\n${pois.map(p => `- ${p.nombre}`).join('\n')}` : '',
    `Genera un resumen breve (máximo 120 palabras) con recomendaciones prácticas, lugares para comer cerca, y consejos útiles para ese día. Responde solo con el texto del resumen, sin JSON ni markdown.`
  ].join('\n');

  try {
    const resumen = await llamarClaude([{ type: 'text', text: promptText }], 800);
    await db.agenda_dias.put({
      viaje_id: currentViajeId,
      fecha: fechaStr,
      alojamiento: ag?.alojamiento || '',
      resumen_ia: resumen.trim()
    });
    await renderTab();
  } catch (e) {
    alert('Error IA: ' + e.message);
  }
}

/* ---------- Estado calendario ---------- */
let calendarioModo = 'mes';
let calendarioFechaRef = new Date();

/* ---------- Navegación ---------- */
function irHome() {
  currentViajeId = null;
  currentTab = 'calendario';
  calendarioModo = 'mes';
  $('#vista-home').classList.remove('hidden');
  $('#vista-viaje').classList.add('hidden');
  $('#bottom-nav').classList.add('hidden');
  $('#btn-back').classList.add('hidden');
  $('#fab').style.bottom = '78px';
  renderHome();
}

async function abrirViaje(id) {
  const v = await db.viajes.get(id);
  currentViajeId = id;
  currentTab = 'calendario';
  calendarioModo = 'mes';
  // Inicializar referencia del calendario al inicio del viaje
  const ini = parseFecha(v?.fecha_inicio);
  calendarioFechaRef = ini ? new Date(ini) : new Date();

  $('#vista-home').classList.add('hidden');
  $('#vista-viaje').classList.remove('hidden');
  $('#bottom-nav').classList.remove('hidden');
  $('#btn-back').classList.remove('hidden');
  $('#fab').style.bottom = '78px';
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === 'calendario'));
  await renderViajeInfo();
  await renderTab();
}

function cambiarTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  $('#vista-dia-detalle').classList.add('hidden');
  $('#tab-content').classList.remove('hidden');
  if (tab === 'calendario') {
    $('#cal-nav').classList.remove('hidden');
  } else {
    $('#cal-nav').classList.add('hidden');
  }
  renderTab();
}

/* ---------- Render Home ---------- */
async function renderHome() {
  const lista = $('#lista-viajes');
  const viajes = await db.viajes.orderBy('creado').reverse().toArray();
  if (!viajes.length) {
    lista.innerHTML = '';
    $('#empty-viajes').classList.remove('hidden');
    return;
  }
  $('#empty-viajes').classList.add('hidden');
  lista.innerHTML = viajes.map((v) => `
    <div class="card" onclick="abrirViaje(${v.id})" style="cursor:pointer">
      <h3>✈️ ${escHTML(v.destino)}</h3>
      <p>${escHTML(v.fecha_inicio)} → ${escHTML(v.fecha_fin)} <span class="badge" style="margin-left:6px">${escHTML(v.estado || 'Planificado')}</span></p>
      <div class="actions" onclick="event.stopPropagation()">
        <button class="btn btn-sm btn-secondary" onclick="editarViaje(${v.id})">✏️ Editar</button>
        <button class="btn btn-sm btn-danger" onclick="eliminarViaje(${v.id})">🗑️</button>
      </div>
    </div>
  `).join('');
}

/* ---------- Render Viaje Info ---------- */
async function renderViajeInfo() {
  const v = await db.viajes.get(currentViajeId);
  if (!v) return irHome();
  $('#viaje-info').innerHTML = `
    <h2>✈️ ${escHTML(v.destino)}</h2>
    <p style="color:var(--text-muted);margin:4px 0 0">${escHTML(v.fecha_inicio)} → ${escHTML(v.fecha_fin)}</p>
    ${v.notas ? `<p style="margin-top:8px;font-size:.9rem">${escHTML(v.notas)}</p>` : ''}
  `;
}

/* ---------- Render Tabs ---------- */
async function renderTab() {
  const container = $('#tab-content');
  container.innerHTML = '<p style="color:var(--text-muted)">Cargando…</p>';
  if (currentTab === 'calendario') await renderCalendario(container);
  else if (currentTab === 'reservas') await renderReservas(container);
  else if (currentTab === 'documentos') await renderDocumentos(container);
  else if (currentTab === 'checklist') await renderChecklist(container);
}

/* ---------- Render Calendario ---------- */
async function renderCalendario(container) {
  try {
    if (calendarioModo === 'mes') await renderCalendarioMes(container, calendarioFechaRef);
    else if (calendarioModo === 'semana') await renderCalendarioSemana(container, calendarioFechaRef);
    else if (calendarioModo === 'ano') await renderCalendarioAno(container, calendarioFechaRef);
  } catch (e) {
    container.innerHTML = `<div class="empty">Error: ${escHTML(e.message)}</div>`;
    console.error(e);
  }
}

async function renderCalendarioMes(container, refDate) {
  try {
    const year = refDate.getFullYear();
    const month = refDate.getMonth();
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const daysInMonth = lastDay.getDate();
    let startDay = firstDay.getDay();
    startDay = startDay === 0 ? 6 : startDay - 1;

    const allEvents = await db.eventos.where({ viaje_id: currentViajeId }).toArray();
    const eventMap = {};
    allEvents.forEach(e => {
      const d = parseFecha(e.fecha_dia);
      if (d && d.getFullYear() === year && d.getMonth() === month) eventMap[d.getDate()] = true;
    });

    const v = await db.viajes.get(currentViajeId);
    const diasViaje = v ? new Set(diasRango(v.fecha_inicio, v.fecha_fin)) : new Set();
    const todayStr = fechaHoy();
    const meses = ['Enero','Febrero','Marzo','Abril','Mayo','Junio','Julio','Agosto','Septiembre','Octubre','Noviembre','Diciembre'];
    $('#cal-titulo').textContent = `${meses[month]} ${year}`;

    let html = '<div class="cal-grid">';
    ['L','M','X','J','V','S','D'].forEach(h => html += `<div class="cal-header">${h}</div>`);
    for (let i = 0; i < startDay; i++) html += '<div class="cal-cell empty"></div>';
    for (let d = 1; d <= daysInMonth; d++) {
      const dateStr = fmtDate(new Date(year, month, d));
      const classes = ['cal-cell'];
      if (dateStr === todayStr) classes.push('today');
      if (eventMap[d]) classes.push('has-events');
      if (!diasViaje.has(dateStr)) classes.push('out-range');
      const click = diasViaje.has(dateStr) ? `onclick="abrirDia('${escAttr(dateStr)}')"` : '';
      html += `<div class="${classes.join(' ')}" ${click}><span class="cal-num">${d}</span>${eventMap[d] ? '<span class="cal-dot"></span>' : ''}</div>`;
    }
    html += '</div>';
    container.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<div class="empty">Error cargando calendario: ${escHTML(e.message)}</div>`;
    console.error(e);
  }
}

async function renderCalendarioSemana(container, refDate) {
  const day = refDate.getDay();
  const diff = refDate.getDate() - (day === 0 ? 6 : day - 1);
  const monday = new Date(refDate);
  monday.setDate(diff);
  monday.setHours(12,0,0,0);

  const allEvents = await db.eventos.where({ viaje_id: currentViajeId }).toArray();
  const eventMap = {};
  allEvents.forEach(e => { eventMap[e.fecha_dia] = (eventMap[e.fecha_dia] || 0) + 1; });

  const v = await db.viajes.get(currentViajeId);
  const diasViaje = new Set(diasRango(v.fecha_inicio, v.fecha_fin));
  const todayStr = fechaHoy();
  const dom = fmtDate(new Date(monday));
  const domFin = fmtDate(new Date(monday.getTime() + 6 * 86400000));
  $('#cal-titulo').textContent = `${dom} → ${domFin}`;

  let html = '<div class="cal-week">';
  const nombres = ['Lun','Mar','Mié','Jue','Vie','Sáb','Dom'];
  for (let i = 0; i < 7; i++) {
    const d = new Date(monday);
    d.setDate(monday.getDate() + i);
    const dateStr = fmtDate(d);
    const count = eventMap[dateStr] || 0;
    const classes = ['cal-week-day'];
    if (dateStr === todayStr) classes.push('today');
    if (count) classes.push('has-events');
    if (!diasViaje.has(dateStr)) classes.push('out-range');
    const click = diasViaje.has(dateStr) ? `onclick="abrirDia('${escAttr(dateStr)}')"` : '';
    html += `<div class="${classes.join(' ')}" ${click}><div class="wd-name">${nombres[i]}</div><div class="wd-num">${d.getDate()}</div><div class="wd-dots">${Array(count).fill('<span class="wd-dot"></span>').join('')}</div></div>`;
  }
  html += '</div>';
  container.innerHTML = html;
}

async function renderCalendarioAno(container, refDate) {
  const year = refDate.getFullYear();
  const allEvents = await db.eventos.where({ viaje_id: currentViajeId }).toArray();
  const countMap = {};
  allEvents.forEach(e => {
    const d = parseFecha(e.fecha_dia);
    if (d && d.getFullYear() === year) countMap[d.getMonth()] = (countMap[d.getMonth()] || 0) + 1;
  });
  $('#cal-titulo').textContent = `Año ${year}`;
  const meses = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'];
  let html = '<div class="cal-year">';
  for (let m = 0; m < 12; m++) {
    const classes = ['cal-year-month'];
    if (countMap[m]) classes.push('has-events');
    html += `<div class="${classes.join(' ')}" onclick="irAMes(${m})"><div class="ym-name">${meses[m]}</div><div class="ym-count">${countMap[m] || 0} eventos</div></div>`;
  }
  html += '</div>';
  container.innerHTML = html;
}

function calendarioAnterior() {
  if (calendarioModo === 'mes') calendarioFechaRef.setMonth(calendarioFechaRef.getMonth() - 1);
  else if (calendarioModo === 'semana') calendarioFechaRef.setDate(calendarioFechaRef.getDate() - 7);
  else if (calendarioModo === 'ano') calendarioFechaRef.setFullYear(calendarioFechaRef.getFullYear() - 1);
  renderTab();
}
function calendarioSiguiente() {
  if (calendarioModo === 'mes') calendarioFechaRef.setMonth(calendarioFechaRef.getMonth() + 1);
  else if (calendarioModo === 'semana') calendarioFechaRef.setDate(calendarioFechaRef.getDate() + 7);
  else if (calendarioModo === 'ano') calendarioFechaRef.setFullYear(calendarioFechaRef.getFullYear() + 1);
  renderTab();
}
function cambiarModoCalendario(modo) {
  calendarioModo = modo;
  document.querySelectorAll('[data-cal]').forEach(t => t.classList.toggle('active', t.dataset.cal === modo));
  renderTab();
}
function irAMes(mes) {
  calendarioFechaRef.setMonth(mes);
  cambiarModoCalendario('mes');
}

function abrirDia(fechaStr) {
  $('#tab-content').classList.add('hidden');
  $('#cal-nav').classList.add('hidden');
  $('#vista-dia-detalle').classList.remove('hidden');
  renderDiaDetalle(fechaStr);
}
function volverACalendario() {
  $('#vista-dia-detalle').classList.add('hidden');
  $('#tab-content').classList.remove('hidden');
  $('#cal-nav').classList.remove('hidden');
}

async function renderDiaDetalle(fechaStr) {
  $('#dia-detalle-titulo').textContent = `${diaSemana(fechaStr)} ${fechaStr}`;
  const allEvents = await db.eventos.where({ viaje_id: currentViajeId }).sortBy('fecha_hora');
  const evs = allEvents.filter(e => e.fecha_dia === fechaStr);
  const ps = await db.puntos_interes.where({ viaje_id: currentViajeId }).toArray();
  const psDia = ps.filter(p => p.fecha === fechaStr);
  const ag = await db.agenda_dias.where({ viaje_id: currentViajeId, fecha: fechaStr }).first();

  const eventoIds = evs.map(e => e.id);
  const adjuntosAll = eventoIds.length ? await db.adjuntos.where('evento_id').anyOf(eventoIds).toArray() : [];
  const eventosConAdjuntos = new Set(adjuntosAll.map(a => a.evento_id));

  const timeline = evs.length ? `<div class="timeline">${evs.map(e => `
    <div class="timeline-item">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:6px">
        <div style="min-width:0">
          <div class="hora">${escHTML(horaDesdeISO(e.fecha_hora))}</div>
          <div class="txt">${iconoTipo(e.tipo)} ${escHTML(e.titulo)} ${e.notas ? `<span style="color:var(--text-muted);font-size:.8rem">(${escHTML(e.notas)})</span>` : ''} ${eventosConAdjuntos.has(e.id) ? `<button style="background:transparent;border:none;padding:0;cursor:pointer;font-size:1rem" onclick="event.stopPropagation();mostrarAdjuntosEvento(${e.id})" title="Ver adjuntos">📎</button>` : ''}</div>
        </div>
        <div style="display:flex;gap:4px;flex-shrink:0">
          <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation();editarEvento(${e.id})">✏️</button>
          <button class="btn btn-sm btn-danger" onclick="event.stopPropagation();eliminarEvento(${e.id})">✕</button>
        </div>
      </div>
    </div>
  `).join('')}</div>` : '<p style="color:var(--text-muted);font-size:.85rem">Sin eventos programados.</p>';

  const poisHtml = psDia.length ? `<div style="margin-top:10px"><strong style="font-size:.8rem;color:var(--text-muted)">📍 Para ver / visitar</strong><div style="margin-top:4px">${psDia.map(p => `<span class="poi-chip">${escHTML(p.nombre)} <button style="background:transparent;border:none;color:var(--danger);padding:0 0 0 4px;cursor:pointer" onclick="eliminarPOI(${p.id})">✕</button></span>`).join('')}</div></div>` : '';
  const resumenHtml = ag?.resumen_ia ? `<div class="resumen-ia"><strong>🤖 Resumen IA</strong><br>${escHTML(ag.resumen_ia)}</div>` : '';

  $('#dia-detalle-body').innerHTML = `
    <div class="day-card" style="margin-bottom:12px">
      <div class="day-header">
        <h4>🏨 ${escHTML(ag?.alojamiento || 'Sin alojamiento')}</h4>
        <button class="btn btn-sm btn-secondary" onclick="editarAlojamiento('${escAttr(fechaStr)}')">Editar</button>
      </div>
      <div class="day-body">
        ${timeline}
        ${poisHtml}
        ${resumenHtml}
        <div class="toolbar" style="margin-top:10px;margin-bottom:0">
          <button class="btn btn-sm btn-secondary" onclick="abrirModalCrearEvento(null,'${escAttr(fechaStr)}')">+ Evento</button>
          <button class="btn btn-sm btn-secondary" onclick="abrirModalCrearPOI('${escAttr(fechaStr)}')">+ Lugar</button>
          <button class="btn btn-sm btn-info" onclick="resumirDiaIA('${escAttr(fechaStr)}')">🤖 Resumir</button>
        </div>
      </div>
    </div>
  `;
}

/* ---------- Render Agenda (lista completa, legacy) ---------- */
async function renderAgenda(container) {
  const v = await db.viajes.get(currentViajeId);
  const dias = diasRango(v.fecha_inicio, v.fecha_fin);
  if (!dias.length) {
    container.innerHTML = '<div class="empty">Define las fechas del viaje para ver la agenda.</div>';
    return;
  }

  const eventosAll = await db.eventos.where({ viaje_id: currentViajeId }).sortBy('fecha_hora');
  const eventos = eventosAll;
  const pois = await db.puntos_interes.where({ viaje_id: currentViajeId }).toArray();
  const agendaDias = await db.agenda_dias.where({ viaje_id: currentViajeId }).toArray();
  const mapAgenda = Object.fromEntries(agendaDias.map(d => [d.fecha, d]));

  // Precargar qué eventos tienen adjuntos
  const eventoIds = eventos.map(e => e.id);
  const adjuntosAll = eventoIds.length ? await db.adjuntos.where('evento_id').anyOf(eventoIds).toArray() : [];
  const eventosConAdjuntos = new Set(adjuntosAll.map(a => a.evento_id));

  container.innerHTML = '';
  for (const fechaStr of dias) {
    const evs = eventos.filter(e => e.fecha_dia === fechaStr);
    const ps = pois.filter(p => p.fecha === fechaStr);
    const ag = mapAgenda[fechaStr];

    const timeline = evs.length ? `<div class="timeline">${evs.map(e => `
      <div class="timeline-item">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:6px">
          <div style="min-width:0">
            <div class="hora">${escHTML(horaDesdeISO(e.fecha_hora))}</div>
            <div class="txt">${iconoTipo(e.tipo)} ${escHTML(e.titulo)} ${e.notas ? `<span style="color:var(--text-muted);font-size:.8rem">(${escHTML(e.notas)})</span>` : ''} ${eventosConAdjuntos.has(e.id) ? `<button style="background:transparent;border:none;padding:0;cursor:pointer;font-size:1rem" onclick="event.stopPropagation();mostrarAdjuntosEvento(${e.id})" title="Ver adjuntos">📎</button>` : ''}</div>
          </div>
          <div style="display:flex;gap:4px;flex-shrink:0">
            <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation();editarEvento(${e.id})">✏️</button>
            <button class="btn btn-sm btn-danger" onclick="event.stopPropagation();eliminarEvento(${e.id})">✕</button>
          </div>
        </div>
      </div>
    `).join('')}</div>` : '<p style="color:var(--text-muted);font-size:.85rem">Sin eventos programados.</p>';

    const poisHtml = ps.length ? `<div style="margin-top:10px"><strong style="font-size:.8rem;color:var(--text-muted)">📍 Para ver / visitar</strong><div style="margin-top:4px">${ps.map(p => `<span class="poi-chip">${escHTML(p.nombre)} <button style="background:transparent;border:none;color:var(--danger);padding:0 0 0 4px;cursor:pointer" onclick="eliminarPOI(${p.id})">✕</button></span>`).join('')}</div></div>` : '';

    const resumenHtml = ag?.resumen_ia ? `<div class="resumen-ia"><strong>🤖 Resumen IA</strong><br>${escHTML(ag.resumen_ia)}</div>` : '';

    const html = `
      <div class="day-card">
        <div class="day-header">
          <h4>📅 ${escHTML(diaSemana(fechaStr))} <span style="font-weight:400">${escHTML(fechaStr)}</span></h4>
          <button class="btn btn-sm btn-secondary" onclick="editarAlojamiento('${escAttr(fechaStr)}')">🏨 ${escHTML(ag?.alojamiento || 'Añadir alojamiento')}</button>
        </div>
        <div class="day-body">
          ${timeline}
          ${poisHtml}
          ${resumenHtml}
          <div class="toolbar" style="margin-top:10px;margin-bottom:0">
            <button class="btn btn-sm btn-secondary" onclick="abrirModalCrearEvento(null,'${escAttr(fechaStr)}')">+ Evento</button>
            <button class="btn btn-sm btn-secondary" onclick="abrirModalCrearPOI('${escAttr(fechaStr)}')">+ Lugar</button>
            <button class="btn btn-sm btn-info" onclick="resumirDiaIA('${escAttr(fechaStr)}')">🤖 Resumir</button>
          </div>
        </div>
      </div>
    `;
    container.insertAdjacentHTML('beforeend', html);
  }
}

/* ---------- Render Reservas ---------- */
async function renderReservas(container) {
  const rows = await db.reservas.where({ viaje_id: currentViajeId }).sortBy('fecha');
  if (!rows.length) { container.innerHTML = '<div class="empty">Sin reservas. Pulsa + para añadir.</div>'; return; }
  container.innerHTML = rows.map((r) => `
    <div class="item">
      <div class="icon">${iconoTipo(r.tipo)}</div>
      <div class="body">
        <p class="title">${escHTML(r.titulo || r.tipo)}</p>
        <p class="meta">${r.localizador ? 'Loc: ' + escHTML(r.localizador) + ' · ' : ''}${escHTML(fmtDate(r.fecha))} ${escHTML(horaDesdeISO(r.fecha))}</p>
      </div>
      <div class="right">
        ${r.localizador ? `<button class="btn btn-sm btn-secondary" onclick="mostrarQR('${escAttr(r.localizador)}','${escAttr(r.titulo || r.tipo)}')">QR</button>` : ''}
        <button class="btn btn-sm btn-secondary" onclick="editarReserva(${r.id})">✏️</button>
        <button class="btn btn-sm btn-danger" onclick="eliminarReserva(${r.id})">✕</button>
      </div>
    </div>
  `).join('');
}

/* ---------- Render Documentos ---------- */
async function renderDocumentos(container) {
  const docs = await db.documentos.where({ viaje_id: currentViajeId }).toArray();
  if (!docs.length) { container.innerHTML = '<div class="empty">Sin documentos. Pulsa + para adjuntar.</div>'; return; }
  container.innerHTML = docs.map((d) => `
    <div class="item">
      <div class="icon">📄</div>
      <div class="body">
        <p class="title">${escHTML(d.nombre)} ${d.cifrado ? '🔒' : ''}</p>
        <p class="meta">${escHTML(d.tipo)}${d.fecha_caducidad ? ' · Cad: ' + escHTML(d.fecha_caducidad) : ''}</p>
      </div>
      <div class="right">
        <button class="btn btn-sm btn-info" onclick="analizarDocumentoIA(${d.id})">🤖</button>
        <button class="btn btn-sm btn-secondary" onclick="compartirDocumento(${d.id})">↗️</button>
        <button class="btn btn-sm btn-secondary" onclick="descargarDocumento(${d.id})">⬇️</button>
        <button class="btn btn-sm btn-danger" onclick="eliminarDocumento(${d.id})">✕</button>
      </div>
    </div>
  `).join('');
}

/* ---------- Render Checklist ---------- */
async function renderChecklist(container) {
  const rows = await db.checklists.where({ viaje_id: currentViajeId }).sortBy('orden');
  if (!rows.length) { container.innerHTML = '<div class="empty">Lista vacía. Pulsa + para añadir ítems.</div>'; return; }
  container.innerHTML = rows.map((c) => `
    <div class="item check-item ${c.completado ? 'completed' : ''}">
      <input type="checkbox" ${c.completado ? 'checked' : ''} onchange="toggleChecklist(${c.id},this.checked)">
      <div class="body">
        <p class="title">${escHTML(c.texto)}</p>
        <p class="meta">${escHTML(c.categoria || 'General')}</p>
      </div>
      <div class="right">
        <button class="btn btn-sm btn-danger" onclick="eliminarChecklist(${c.id})">✕</button>
      </div>
    </div>
  `).join('');
}

function iconoTipo(tipo) {
  const map = {
    vuelo: '✈️', hotel: '🏨', tren: '🚆', bus: '🚌', barco: '⛴️', coche: '🚗',
    actividad: '🎯', restaurante: '🍽️', comida: '🍽️', seguro: '🛡️',
    pasaporte: '🛂', dni: '🆔', visado: '🛂', ics: '📅', adjunto: '📎', otros: '📌'
  };
  return map[(tipo || '').toLowerCase()] || '📌';
}

/* ---------- FAB ---------- */
function fabClick() {
  if (!currentViajeId) return abrirModalCrearViaje();
  if (currentTab === 'calendario') return abrirModalCrearEvento();
  if (currentTab === 'reservas') return abrirModalCrearReserva();
  if (currentTab === 'documentos') return abrirModalCrearDocumento();
  if (currentTab === 'checklist') return abrirModalCrearChecklist();
}

/* ---------- Modales genéricos ---------- */
function abrirModal(titulo, html, onConfirm) {
  $('#modal-titulo').textContent = titulo;
  $('#modal-body').innerHTML = html;
  $('#modal').classList.remove('hidden');
  modalConfirmFn = onConfirm;
}
function cerrarModalDirecto() { $('#modal').classList.add('hidden'); modalConfirmFn = null; }
function modalConfirmar() { if (modalConfirmFn) modalConfirmFn(); }
function cerrarModal(ev) { if (ev.target === $('#modal')) cerrarModalDirecto(); }

/* ---------- Viaje CRUD ---------- */
function abrirModalCrearViaje(editId) {
  const esEdit = !!editId;
  const prom = esEdit ? db.viajes.get(editId) : Promise.resolve({});
  prom.then((v) => {
    abrirModal(esEdit ? 'Editar viaje' : 'Nuevo viaje', `
      <label>Destino</label><input id="f-destino" value="${escAttr(v.destino || '')}">
      <label>Inicio (dd/mm/aaaa)</label><input id="f-inicio" class="input-fecha" placeholder="dd/mm/aaaa" value="${escAttr(v.fecha_inicio || '')}">
      <label>Fin (dd/mm/aaaa)</label><input id="f-fin" class="input-fecha" placeholder="dd/mm/aaaa" value="${escAttr(v.fecha_fin || '')}">
      <label>Estado</label>
      <select id="f-estado">
        <option value="Planificado" ${v.estado === 'Planificado' ? 'selected' : ''}>Planificado</option>
        <option value="En curso" ${v.estado === 'En curso' ? 'selected' : ''}>En curso</option>
        <option value="Finalizado" ${v.estado === 'Finalizado' ? 'selected' : ''}>Finalizado</option>
      </select>
      <label>Notas</label><textarea id="f-notas">${escHTML(v.notas || '')}</textarea>
    `, async () => {
      const ini = $('#f-inicio').value;
      const fin = $('#f-fin').value;
      if (!parseFecha(ini) || !parseFecha(fin)) { alert('Formato de fecha inválido. Usa dd/mm/aaaa'); return; }
      const data = {
        destino: $('#f-destino').value,
        fecha_inicio: ini,
        fecha_fin: fin,
        estado: $('#f-estado').value,
        notas: $('#f-notas').value,
        creado: v.creado || Date.now()
      };
      if (esEdit) await db.viajes.update(editId, data); else await db.viajes.add(data);
      cerrarModalDirecto();
      if (esEdit && currentViajeId) { await renderViajeInfo(); await renderTab(); }
      else renderHome();
    });
  });
}
function editarViaje(id) { abrirModalCrearViaje(id); }
async function eliminarViaje(id) {
  if (!confirm('¿Eliminar viaje y TODO su contenido?')) return;
  await db.viajes.delete(id);
  await db.reservas.where({ viaje_id: id }).delete();
  await db.eventos.where({ viaje_id: id }).delete();
  await db.checklists.where({ viaje_id: id }).delete();
  await db.agenda_dias.where({ viaje_id: id }).delete();
  await db.puntos_interes.where({ viaje_id: id }).delete();
  const docs = await db.documentos.where({ viaje_id: id }).toArray();
  for (const d of docs) { await db.archivos.where({ doc_id: d.id }).delete(); }
  await db.documentos.where({ viaje_id: id }).delete();
  renderHome();
}

/* ---------- Reserva CRUD ---------- */
function marcaReserva(id) { return `__RESERVA_ID__:${id}__`; }

async function buscarEventoDeReserva(reservaId) {
  const marca = marcaReserva(reservaId);
  const all = await db.eventos.where({ viaje_id: currentViajeId }).toArray();
  return all.find(e => (e.notas || '').includes(marca));
}

function abrirModalCrearReserva(editId) {
  const prom = editId ? db.reservas.get(editId) : Promise.resolve({});
  prom.then((r) => {
    abrirModal(editId ? 'Editar reserva' : 'Nueva reserva', `
      <label>Tipo</label>
      <select id="f-tipo">
        <option value="vuelo">✈️ Vuelo</option><option value="hotel">🏨 Hotel</option>
        <option value="tren">🚆 Tren</option><option value="bus">🚌 Bus</option>
        <option value="barco">⛴️ Barco</option><option value="coche">🚗 Coche</option>
        <option value="actividad">🎯 Actividad</option><option value="restaurante">🍽️ Restaurante</option>
        <option value="otros">📌 Otros</option>
      </select>
      <label>Título</label><input id="f-titulo" value="${escAttr(r.titulo || '')}">
      <label>Localizador</label><input id="f-loc" value="${escAttr(r.localizador || '')}">
      <div style="display:flex;gap:10px;align-items:flex-end">
        <div style="flex:1">
          <label>Fecha</label><input id="f-fecha" class="input-fecha" placeholder="dd/mm/aaaa" value="${escAttr(r.fecha ? fmtDate(r.fecha) : '')}">
        </div>
        <div style="width:110px;flex-shrink:0">
          <label>Hora</label><input type="time" id="f-hora" value="${escAttr(r.fecha ? horaDesdeISO(r.fecha) : '')}">
        </div>
      </div>
      <label>Notas</label><textarea id="f-notas">${escHTML(r.notas || '')}</textarea>
      <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-top:10px;flex-wrap:wrap"><input type="checkbox" id="f-cita" checked> 📅 Cita en calendario</label>
      <label>Adjuntar documento (opcional)</label><input type="file" id="f-adjunto">
    `, async () => {
      const fStr = $('#f-fecha').value;
      const hStr = $('#f-hora').value;
      const iso = fechaHoraToISO(fStr, hStr);
      const data = {
        viaje_id: currentViajeId,
        tipo: $('#f-tipo').value,
        titulo: $('#f-titulo').value,
        localizador: $('#f-loc').value,
        fecha: iso,
        notas: $('#f-notas').value
      };
      let reservaId = editId;
      if (editId) {
        await db.reservas.update(editId, data);
      } else {
        reservaId = await db.reservas.add(data);
      }

      // Adjuntar archivo si hay
      const fileInput = $('#f-adjunto');
      if (fileInput && fileInput.files && fileInput.files.length) {
        await guardarAdjunto(null, fileInput.files[0]); // null eventoId => documento suelto
      }

      // Sincronizar evento/cita
      if ($('#f-cita').checked && iso) {
        const marca = marcaReserva(reservaId);
        const evExistente = await buscarEventoDeReserva(reservaId);
        const evData = {
          viaje_id: currentViajeId,
          tipo: data.tipo,
          titulo: data.titulo,
          fecha_hora: iso,
          fecha_dia: fStr,
          notas: [data.notas, marca].filter(Boolean).join(' | ')
        };
        if (evExistente) {
          await db.eventos.update(evExistente.id, evData);
        } else {
          await db.eventos.add(evData);
        }
      }

      cerrarModalDirecto(); await renderTab();
    });
    if (r.tipo) $('#f-tipo').value = r.tipo;
  });
}
function editarReserva(id) { abrirModalCrearReserva(id); }
async function eliminarReserva(id) {
  if (!confirm('¿Eliminar reserva?')) return;
  const ev = await buscarEventoDeReserva(id);
  if (ev) await db.eventos.delete(ev.id);
  await db.reservas.delete(id);
  await renderTab();
}

/* ---------- Evento CRUD ---------- */
function abrirModalCrearEvento(editId, fechaPre) {
  const prom = editId ? db.eventos.get(editId) : Promise.resolve({});
  prom.then((ev) => {
    const fPre = fechaPre || (ev.fecha_dia || '');
    const hPre = ev.fecha_hora ? horaDesdeISO(ev.fecha_hora) : '';
    abrirModal(editId ? 'Editar evento' : 'Nuevo evento', `
      <label>Tipo</label>
      <select id="f-tipo">
        <option value="vuelo">✈️ Vuelo</option><option value="hotel">🏨 Hotel</option>
        <option value="tren">🚆 Tren</option><option value="bus">🚌 Bus</option>
        <option value="barco">⛴️ Barco</option><option value="coche">🚗 Coche</option>
        <option value="actividad">🎯 Actividad</option><option value="restaurante">🍽️ Restaurante</option>
        <option value="otros">📌 Otros</option>
      </select>
      <label>Título</label><input id="f-titulo" value="${escAttr(ev.titulo || '')}">
      <div style="display:flex;gap:10px;align-items:flex-end">
        <div style="flex:1">
          <label>Fecha</label><input id="f-fecha" class="input-fecha" placeholder="dd/mm/aaaa" value="${escAttr(fPre)}">
        </div>
        <div style="width:110px;flex-shrink:0">
          <label>Hora</label><input type="time" id="f-hora" value="${escAttr(hPre)}">
        </div>
      </div>
      <label>Notas</label><textarea id="f-notas">${escHTML(ev.notas || '')}</textarea>
      <label>Adjuntar archivo (opcional)</label><input type="file" id="f-adjunto">
    `, async () => {
      const fStr = $('#f-fecha').value;
      const hStr = $('#f-hora').value;
      if (!parseFecha(fStr)) { alert('Fecha inválida. Usa dd/mm/aaaa'); return; }
      const iso = fechaHoraToISO(fStr, hStr);
      const data = {
        viaje_id: currentViajeId,
        tipo: $('#f-tipo').value,
        titulo: $('#f-titulo').value,
        fecha_hora: iso,
        fecha_dia: fStr,
        notas: $('#f-notas').value
      };
      let eventoId = editId;
      if (editId) await db.eventos.update(editId, data);
      else eventoId = await db.eventos.add(data);

      const fileInput = $('#f-adjunto');
      if (fileInput && fileInput.files && fileInput.files.length) {
        await guardarAdjunto(eventoId, fileInput.files[0]);
      }

      cerrarModalDirecto(); await renderTab();
    });
    if (ev.tipo) $('#f-tipo').value = ev.tipo;
  });
}
function editarEvento(id) { abrirModalCrearEvento(id); }
async function eliminarEvento(id) { if (confirm('¿Eliminar evento?')) { await db.eventos.delete(id); await renderTab(); } }

/* ---------- Punto de Interés CRUD ---------- */
function abrirModalCrearPOI(fechaPre) {
  abrirModal('Añadir lugar para ver', `
    <label>Fecha</label><input id="f-fecha" class="input-fecha" placeholder="dd/mm/aaaa" value="${escAttr(fechaPre || '')}">
    <label>Nombre del lugar</label><input id="f-nombre" placeholder="Ej: Museo del Prado">
    <label>Tipo</label>
    <select id="f-tipo"><option value="turismo">Turismo</option><option value="comida">Comida</option><option value="naturaleza">Naturaleza</option><option value="compras">Compras</option><option value="otro">Otro</option></select>
  `, async () => {
    const fStr = $('#f-fecha').value;
    if (!parseFecha(fStr)) { alert('Fecha inválida'); return; }
    await db.puntos_interes.add({
      viaje_id: currentViajeId,
      fecha: fStr,
      nombre: $('#f-nombre').value,
      tipo: $('#f-tipo').value
    });
    cerrarModalDirecto(); await renderTab();
  });
}
async function eliminarPOI(id) { if (confirm('¿Quitar lugar?')) { await db.puntos_interes.delete(id); await renderTab(); } }

/* ---------- Alojamiento / Agenda día ---------- */
function editarAlojamiento(fechaStr) {
  db.agenda_dias.where({ viaje_id: currentViajeId, fecha: fechaStr }).first().then((ag) => {
    abrirModal('Alojamiento del día', `
      <label>Fecha</label><input readonly value="${escAttr(fechaStr)}">
      <label>Nombre del alojamiento</label><input id="f-aloja" placeholder="Ej: Hotel Gran Vía" value="${escAttr(ag?.alojamiento || '')}">
      <label>Notas del día (opcional)</label><textarea id="f-notas-dia">${escHTML(ag?.notas_dia || '')}</textarea>
    `, async () => {
      await db.agenda_dias.put({
        viaje_id: currentViajeId,
        fecha: fechaStr,
        alojamiento: $('#f-aloja').value,
        notas_dia: $('#f-notas-dia').value,
        resumen_ia: ag?.resumen_ia || ''
      });
      cerrarModalDirecto(); await renderTab();
    });
  });
}

/* ---------- Checklist CRUD ---------- */
function abrirModalCrearChecklist() {
  abrirModal('Nuevo ítem checklist', `
    <label>Categoría</label>
    <input id="f-cat" list="cats" placeholder="Equipaje, Documentos, Electrónica…">
    <datalist id="cats"><option value="Equipaje"><option value="Documentos"><option value="Electrónica"><option value="Higiene"><option value="Salud"><option value="Otros"></datalist>
    <label>Ítem</label><input id="f-texto" placeholder="Ej: Pasaporte">
  `, async () => {
    const count = await db.checklists.where({ viaje_id: currentViajeId }).count();
    await db.checklists.add({
      viaje_id: currentViajeId,
      categoria: $('#f-cat').value || 'General',
      texto: $('#f-texto').value,
      completado: 0,
      orden: count
    });
    cerrarModalDirecto(); await renderTab();
    if (navigator.vibrate) navigator.vibrate(40);
  });
}
async function toggleChecklist(id, checked) {
  await db.checklists.update(id, { completado: checked ? 1 : 0 });
  await renderTab();
  if (checked && navigator.vibrate) navigator.vibrate([30, 50, 30]);
}
async function eliminarChecklist(id) { if (confirm('¿Eliminar ítem?')) { await db.checklists.delete(id); await renderTab(); } }

/* ---------- Documentos CRUD + Cifrado ---------- */
function abrirModalCrearDocumento() {
  abrirModal('Adjuntar documento', `
    <label>Nombre</label><input id="f-nombre" placeholder="Ej: Pasaporte Juan">
    <label>Tipo</label>
    <select id="f-tipo-doc"><option value="pasaporte">Pasaporte</option><option value="dni">DNI</option><option value="visado">Visado</option><option value="seguro">Seguro</option><option value="reserva">Reserva</option><option value="otro">Otro</option></select>
    <label>Fecha caducidad (dd/mm/aaaa, opcional)</label><input id="f-caduca" class="input-fecha" placeholder="dd/mm/aaaa">
    <label>Archivo</label><input type="file" id="f-archivo">
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-top:10px"><input type="checkbox" id="f-cifrar" checked> Cifrar archivo</label>
    <p style="font-size:.8rem;color:var(--text-muted)">Si cifras, se requiere tu contraseña maestra para descargarlo después.</p>
  `, async () => {
    const fileInput = $('#f-archivo');
    if (!fileInput.files.length) { alert('Selecciona un archivo'); return; }
    const file = fileInput.files[0];
    const buffer = await file.arrayBuffer();
    let blobToStore = new Uint8Array(buffer);
    let cifrado = 0, salt = null, iv = null;

    if ($('#f-cifrar').checked) {
      try {
        const pw = ensurePassword();
        const enc = await encryptBuffer(buffer, pw);
        blobToStore = enc.data; salt = enc.salt; iv = enc.iv; cifrado = 1;
      } catch (e) { alert('Error al cifrar: ' + e.message); return; }
    }

    const c = $('#f-caduca').value;
    const docId = await db.documentos.add({
      viaje_id: currentViajeId,
      nombre: $('#f-nombre').value || file.name,
      tipo: $('#f-tipo-doc').value,
      tags: [],
      fecha_caducidad: c && parseFecha(c) ? c : null,
      cifrado
    });

    await db.archivos.add({
      doc_id: docId,
      nombre: file.name,
      mimeType: file.type || 'application/octet-stream',
      blob: blobToStore,
      salt,
      iv
    });

    cerrarModalDirecto(); await renderTab();
  });
}

async function descargarDocumento(docId) {
  const doc = await db.documentos.get(docId);
  const arch = await db.archivos.where({ doc_id: docId }).first();
  if (!arch) { alert('Archivo no encontrado'); return; }
  let finalBuffer = arch.blob;

  if (doc.cifrado) {
    const pw = prompt('Este documento está cifrado. Introduce contraseña maestra:');
    if (!pw) return;
    try {
      finalBuffer = await decryptBuffer(arch.blob, arch.salt, arch.iv, pw);
    } catch (e) { alert('Contraseña incorrecta o archivo corrupto'); return; }
  }

  const blob = new Blob([finalBuffer], { type: arch.mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = arch.nombre; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function compartirDocumento(docId) {
  const doc = await db.documentos.get(docId);
  const arch = await db.archivos.where({ doc_id: docId }).first();
  if (!arch) { alert('Archivo no encontrado'); return; }
  let finalBuffer = arch.blob;
  if (doc.cifrado) {
    const pw = prompt('Documento cifrado. Introduce contraseña maestra para compartir:');
    if (!pw) return;
    try { finalBuffer = await decryptBuffer(arch.blob, arch.salt, arch.iv, pw); }
    catch (e) { alert('Contraseña incorrecta'); return; }
  }
  const file = new File([finalBuffer], arch.nombre, { type: arch.mimeType });
  if (navigator.canShare && navigator.canShare({ files: [file] })) {
    try {
      await navigator.share({ files: [file], title: doc.nombre });
    } catch (e) { if (e.name !== 'AbortError') alert('Error al compartir: ' + e.message); }
  } else {
    const url = URL.createObjectURL(file);
    const a = document.createElement('a');
    a.href = url; a.download = arch.nombre; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
}

async function eliminarDocumento(id) {
  if (!confirm('¿Eliminar documento?')) return;
  await db.adjuntos.where({ doc_id: id }).delete();
  await db.archivos.where({ doc_id: id }).delete();
  await db.documentos.delete(id);
  await renderTab();
}

/* ---------- Adjuntos a eventos ---------- */
async function guardarAdjunto(eventoId, file) {
  const buffer = await file.arrayBuffer();
  let blobToStore = new Uint8Array(buffer);
  let cifrado = 0, salt = null, iv = null;

  const docId = await db.documentos.add({
    viaje_id: currentViajeId,
    nombre: file.name,
    tipo: eventoId ? 'adjunto' : 'reserva',
    tags: eventoId ? ['evento_' + eventoId] : ['reserva'],
    fecha_caducidad: null,
    cifrado
  });

  await db.archivos.add({
    doc_id: docId,
    nombre: file.name,
    mimeType: file.type || 'application/octet-stream',
    blob: blobToStore,
    salt,
    iv
  });

  if (eventoId) await db.adjuntos.add({ evento_id: eventoId, doc_id: docId });
  return docId;
}

async function obtenerAdjuntos(eventoId) {
  const links = await db.adjuntos.where({ evento_id: eventoId }).toArray();
  const docs = [];
  for (const l of links) {
    const d = await db.documentos.get(l.doc_id);
    if (d) docs.push(d);
  }
  return docs;
}

async function mostrarAdjuntosEvento(eventoId) {
  const docs = await obtenerAdjuntos(eventoId);
  if (!docs.length) { alert('Este evento no tiene archivos adjuntos'); return; }
  abrirModal('Archivos del evento', docs.map(d => `
    <div class="item">
      <div class="icon">📎</div>
      <div class="body">
        <p class="title">${escHTML(d.nombre)}</p>
        <p class="meta">${escHTML(d.tipo)}</p>
      </div>
      <div class="right">
        <button class="btn btn-sm btn-secondary" onclick="descargarDocumento(${d.id})">⬇️</button>
        <button class="btn btn-sm btn-danger" onclick="eliminarAdjunto(${eventoId},${d.id})">✕</button>
      </div>
    </div>
  `).join(''), null);
  $('#modal-ok').textContent = 'Cerrar';
  modalConfirmFn = cerrarModalDirecto;
}

async function eliminarAdjunto(eventoId, docId) {
  if (!confirm('¿Quitar este adjunto del evento?')) return;
  await db.adjuntos.where({ evento_id: eventoId, doc_id: docId }).delete();
  await renderTab();
  mostrarAdjuntosEvento(eventoId);
}

/* ---------- QR + Wake Lock ---------- */
async function mostrarQR(texto, titulo) {
  if (!texto) return;
  $('#qr-titulo').textContent = titulo || 'Código QR';
  $('#qr-modal').classList.remove('hidden');
  await QRCode.toCanvas($('#qr-canvas'), texto, { width: 300, margin: 2, color: { dark: '#000', light: '#fff' } });
  try {
    if ('wakeLock' in navigator) wakeLockObj = await navigator.wakeLock.request('screen');
  } catch (e) { console.log('Wake lock no disponible', e); }
}
function cerrarQR() {
  $('#qr-modal').classList.add('hidden');
  if (wakeLockObj) { wakeLockObj.release().catch(()=>{}); wakeLockObj = null; }
}

/* ---------- Parser iCalendar (.ics) ---------- */
function parseICS(text) {
  const unfolded = text.replace(/\r?\n[ \t]/g, '');
  const lines = unfolded.split(/\r?\n/);
  const events = [];
  let current = null;

  for (const line of lines) {
    if (line === 'BEGIN:VEVENT') {
      current = { summary: '', description: '', location: '', start: '', end: '', uid: '' };
    } else if (line === 'END:VEVENT') {
      if (current && current.start) events.push(current);
      current = null;
    } else if (current) {
      const idx = line.indexOf(':');
      if (idx === -1) continue;
      const key = line.slice(0, idx).toUpperCase().split(';')[0];
      const value = line.slice(idx + 1);
      if (key === 'SUMMARY') current.summary = value;
      else if (key === 'DESCRIPTION') current.description = value;
      else if (key === 'LOCATION') current.location = value;
      else if (key === 'UID') current.uid = value;
      else if (key === 'DTSTART') current.start = parseICSDate(value);
      else if (key === 'DTEND') current.end = parseICSDate(value);
    }
  }
  return events;
}

function parseICSDate(str) {
  if (!str) return null;
  const isUTC = str.endsWith('Z');
  const clean = str.replace('Z', '');
  if (clean.length === 8) {
    const y = parseInt(clean.slice(0, 4), 10), m = parseInt(clean.slice(4, 6), 10), d = parseInt(clean.slice(6, 8), 10);
    return new Date(y, m - 1, d, 12, 0, 0).toISOString();
  }
  if (clean.length >= 15 && clean.includes('T')) {
    const y = parseInt(clean.slice(0, 4), 10), m = parseInt(clean.slice(4, 6), 10), d = parseInt(clean.slice(6, 8), 10);
    const h = parseInt(clean.slice(9, 11), 10), min = parseInt(clean.slice(11, 13), 10);
    if (isUTC) return new Date(Date.UTC(y, m - 1, d, h, min)).toISOString();
    return new Date(y, m - 1, d, h, min).toISOString();
  }
  const d = new Date(clean);
  return isNaN(d) ? null : d.toISOString();
}

function detectarTipoICS(summary, description) {
  const text = ((summary || '') + ' ' + (description || '')).toLowerCase();
  if (text.includes('vuelo') || text.includes('flight') || text.includes('boarding') || text.includes('departure') || text.includes('arrival') || text.includes('aeropuerto') || text.includes('airport') || text.includes('iberia') || text.includes('ryanair') || text.includes('vueling') || text.includes('easyjet') || text.includes('lufthansa') || text.includes('air france')) return 'vuelo';
  if (text.includes('hotel') || text.includes('alojamiento') || text.includes('hostal') || text.includes('resort') || text.includes('booking') || text.includes('airbnb') || text.includes('habitación') || text.includes('room')) return 'hotel';
  if (text.includes('tren') || text.includes('train') || text.includes('renfe') || text.includes('ave') || text.includes('railway') || text.includes('sncf') || text.includes('tgv') || text.includes('eurostar')) return 'tren';
  if (text.includes('bus') || text.includes('autobús') || text.includes('coach') || text.includes('flixbus')) return 'bus';
  if (text.includes('barco') || text.includes('ferry') || text.includes('crucero') || text.includes('cruise') || text.includes('ship')) return 'barco';
  if (text.includes('coche') || text.includes('car') || text.includes('rental') || text.includes('alquiler') || text.includes('rent-a-car') || text.includes('sixt') || text.includes('avis') || text.includes('hertz') || text.includes('europcar') || text.includes('enterprise')) return 'coche';
  if (text.includes('restaurante') || text.includes('comida') || text.includes('cena') || text.includes('lunch') || text.includes('dinner') || text.includes('breakfast') || text.includes('desayuno')) return 'restaurante';
  if (text.includes('actividad') || text.includes('tour') || text.includes('visita') || text.includes('entradas') || text.includes('tickets') || text.includes('excursión')) return 'actividad';
  return 'otros';
}

async function procesarICS(input) {
  const file = input.files[0];
  if (!file) return;
  const text = await file.text();
  const eventos = parseICS(text);
  if (!eventos.length) { alert('No se encontraron eventos en el archivo .ics'); input.value = ''; return; }

  // Guardar archivo .ics original como documento
  const buffer = await file.arrayBuffer();
  const docId = await db.documentos.add({
    viaje_id: currentViajeId,
    nombre: file.name,
    tipo: 'ics',
    tags: [],
    fecha_caducidad: null,
    cifrado: 0
  });
  await db.archivos.add({
    doc_id: docId,
    nombre: file.name,
    mimeType: 'text/calendar',
    blob: new Uint8Array(buffer),
    salt: null,
    iv: null
  });

  const listaHtml = eventos.map((ev, i) => `
    <div class="item" style="align-items:flex-start;margin-bottom:8px">
      <input type="checkbox" id="ics-chk-${i}" checked style="width:24px;height:24px;accent-color:var(--accent);margin-top:2px;flex-shrink:0">
      <div class="body" style="margin-left:8px">
        <p class="title">${escHTML(ev.summary || 'Sin título')}</p>
        <p class="meta">${escHTML(fmtDate(ev.start))} ${escHTML(horaDesdeISO(ev.start))}${ev.location ? ' · ' + escHTML(ev.location) : ''}</p>
        ${ev.description ? `<p class="meta">${escHTML(ev.description.substring(0, 120))}${ev.description.length > 120 ? '...' : ''}</p>` : ''}
      </div>
    </div>
  `).join('');

  abrirModal(`Importar ${eventos.length} evento(s)`, `
    <p style="color:var(--text-muted);font-size:.9rem;margin-bottom:10px">Selecciona los que quieres añadir a este viaje:</p>
    <div style="max-height:50vh;overflow-y:auto">${listaHtml}</div>
  `, async () => {
    let importados = 0;
    for (let i = 0; i < eventos.length; i++) {
      if ($('#ics-chk-' + i).checked) {
        const ev = eventos[i];
        await db.eventos.add({
          viaje_id: currentViajeId,
          fecha_hora: ev.start,
          fecha_dia: fmtDate(ev.start),
          tipo: detectarTipoICS(ev.summary, ev.description),
          titulo: ev.summary || 'Evento importado',
          notas: [ev.description, ev.location].filter(Boolean).join(' · ')
        });
        importados++;
      }
    }
    cerrarModalDirecto();
    alert(`${importados} evento(s) importados`);
    await renderTab();
  });
  input.value = '';
}

/* ---------- Export / Import ---------- */
async function exportarTodo() {
  const data = {
    viajes: await db.viajes.toArray(),
    reservas: await db.reservas.toArray(),
    eventos: await db.eventos.toArray(),
    checklists: await db.checklists.toArray(),
    documentos: await db.documentos.toArray(),
    archivos: await db.archivos.toArray(),
    agenda_dias: await db.agenda_dias.toArray(),
    puntos_interes: await db.puntos_interes.toArray(),
    config: await db.config.toArray(),
    exportado: new Date().toISOString()
  };
  data.archivos = data.archivos.map((a) => ({ ...a, blob: Array.from(a.blob) }));
  const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `bunker-backup-${fechaHoy().replace(/\//g,'-')}.json`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function importarTodo(input) {
  const file = input.files[0]; if (!file) return;
  const text = await file.text();
  try {
    const data = JSON.parse(text);
    if (!confirm(`Esto REEMPLAZARÁ todos los datos actuales por los del backup de ${data.exportado || 'fecha desconocida'}. ¿Continuar?`)) return;
    await db.viajes.clear(); await db.reservas.clear(); await db.eventos.clear();
    await db.checklists.clear(); await db.documentos.clear(); await db.archivos.clear();
    await db.agenda_dias.clear(); await db.puntos_interes.clear(); await db.config.clear();

    if (data.viajes?.length) await db.viajes.bulkAdd(data.viajes);
    if (data.reservas?.length) await db.reservas.bulkAdd(data.reservas);
    if (data.eventos?.length) await db.eventos.bulkAdd(data.eventos);
    if (data.checklists?.length) await db.checklists.bulkAdd(data.checklists);
    if (data.documentos?.length) await db.documentos.bulkAdd(data.documentos);
    if (data.archivos?.length) {
      const fixed = data.archivos.map((a) => ({ ...a, blob: new Uint8Array(a.blob) }));
      await db.archivos.bulkAdd(fixed);
    }
    if (data.agenda_dias?.length) await db.agenda_dias.bulkAdd(data.agenda_dias);
    if (data.puntos_interes?.length) await db.puntos_interes.bulkAdd(data.puntos_interes);
    if (data.config?.length) await db.config.bulkAdd(data.config);

    alert('Importación completada');
    irHome();
  } catch (e) { alert('Error al importar: ' + e.message); console.error(e); }
  input.value = '';
}

async function borrarTodo() {
  if (!confirm('⚠️ ¿Borrar TODOS los datos? No se puede deshacer.')) return;
  await db.delete();
  location.reload();
}

/* ---------- Validación API Key Claude ---------- */
async function validarClaveAPI(key) {
  if (!key) return { ok: false, msg: 'Sin key' };
  const proxy = await getConfig('claude_proxy');
  try {
    const res = await fetch(proxy || 'https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ model: 'claude-3-haiku-20240307', max_tokens: 10, messages: [{ role: 'user', content: 'hi' }] })
    });
    if (res.status === 401) return { ok: false, msg: 'Key inválida' };
    if (res.status === 403) return { ok: false, msg: 'Key sin permisos' };
    if (!res.ok) return { ok: false, msg: `Error ${res.status}` };
    return { ok: true, msg: 'Key activa' };
  } catch (e) {
    return { ok: false, msg: proxy ? 'Proxy no responde' : 'Sin conexión (CORS bloqueado)' };
  }
}

/* ---------- PIN de acceso ---------- */
function maskKey(key) {
  if (!key || key.length < 8) return '';
  return '••••••••••••' + key.slice(-4);
}

async function requierePIN() {
  const pin = await getConfig('app_pin');
  if (!pin) return true;
  const input = prompt('🔒 Introduce tu PIN para continuar:');
  if (input === null) return false;
  if (input !== pin) { alert('PIN incorrecto'); return false; }
  return true;
}

function mostrarConfigIA() {
  Promise.all([getConfig('claude_api_key'), getConfig('claude_model'), getConfig('claude_proxy')]).then(async ([key, model, proxy]) => {
    const check = key ? await validarClaveAPI(key) : { ok: false, msg: 'Sin key' };
    const statusColor = check.ok ? 'var(--success)' : 'var(--danger)';
    const statusDot = check.ok ? '🟢' : '🔴';
    const masked = maskKey(key || '');
    abrirModal('Configurar Claude IA', `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
        <span style="font-size:1.2rem">${statusDot}</span>
        <span style="color:${statusColor};font-weight:700;font-size:.9rem">${check.msg}</span>
      </div>
      <label>API Key de Anthropic</label>
      <div style="display:flex;gap:6px">
        <input id="cfg-key" type="password" placeholder="sk-ant-..." value="${escAttr(key || '')}" style="flex:1">
        <button type="button" class="btn btn-sm btn-secondary" onclick="const i=document.getElementById('cfg-key');i.type=i.type==='password'?'text':'password'">👁️</button>
      </div>
      <p id="cfg-status" style="font-size:.8rem;margin-top:6px;color:var(--text-muted)">${masked ? 'Key guardada: ' + masked : 'Sin key guardada'}</p>
      <label>Modelo</label>
      <select id="cfg-model">
        <option value="claude-3-haiku-20240307" ${model !== 'claude-3-sonnet-20241022' ? 'selected' : ''}>Claude 3 Haiku (rápido/barato)</option>
        <option value="claude-3-sonnet-20241022" ${model === 'claude-3-sonnet-20241022' ? 'selected' : ''}>Claude 3.5 Sonnet (más capaz)</option>
      </select>
      <label>Proxy URL (solo si da error CORS)</label>
      <input id="cfg-proxy" placeholder="https://tu-proxy.workers.dev" value="${escAttr(proxy || '')}">
      <p style="font-size:.7rem;color:var(--text-muted);margin-top:4px">Si pones un proxy, la app enviará las peticiones ahí en vez de directamente a Anthropic.</p>
      <div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-sm btn-secondary" onclick="probarKeyClaude()">🧪 Probar key</button>
      </div>
      <p style="font-size:.75rem;color:var(--text-muted);margin-top:10px">
        Tu API key se guarda solo en este dispositivo. Nunca se comparte.
      </p>
    `, async () => {
      const nuevaKey = $('#cfg-key').value.trim();
      const nuevoProxy = $('#cfg-proxy').value.trim();
      if (nuevaKey) {
        const check = await validarClaveAPI(nuevaKey);
        if (!check.ok) { alert(check.msg + '\n\nLa key no se ha guardado.'); return; }
      }
      await setConfig('claude_api_key', nuevaKey);
      await setConfig('claude_model', $('#cfg-model').value);
      await setConfig('claude_proxy', nuevoProxy);
      cerrarModalDirecto();
      alert('✅ Configuración guardada');
    });
  });
}

async function probarKeyClaude() {
  const key = $('#cfg-key').value.trim();
  const proxy = $('#cfg-proxy').value.trim();
  const status = $('#cfg-status');
  status.textContent = '🔄 Comprobando...';
  status.style.color = 'var(--text-muted)';
  const check = await validarClaveAPI(key);
  status.style.color = check.ok ? 'var(--success)' : 'var(--danger)';
  status.textContent = (check.ok ? '🟢 ' : '🔴 ') + check.msg;
}

function mostrarConfigPIN() {
  getConfig('app_pin').then((pin) => {
    abrirModal('PIN de acceso', `
      <label>PIN actual: ${pin ? '••••••' : 'Sin PIN'}</label>
      <input id="pin-nuevo" type="password" inputmode="numeric" maxlength="6" placeholder="Nuevo PIN (4-6 dígitos)">
      <input id="pin-repite" type="password" inputmode="numeric" maxlength="6" placeholder="Repite PIN" style="margin-top:8px">
      <p style="font-size:.8rem;color:var(--text-muted);margin-top:8px">Deja ambos vacíos y guarda para eliminar el PIN.</p>
    `, async () => {
      const n = $('#pin-nuevo').value.trim();
      const r = $('#pin-repite').value.trim();
      if (!n && !r) {
        await setConfig('app_pin', '');
        cerrarModalDirecto();
        alert('PIN eliminado');
        return;
      }
      if (n.length < 4) { alert('El PIN debe tener al menos 4 dígitos'); return; }
      if (n !== r) { alert('Los PIN no coinciden'); return; }
      await setConfig('app_pin', n);
      cerrarModalDirecto();
      alert('PIN guardado. La próxima vez se pedirá al abrir la app.');
    });
  });
}

async function verificarBloqueo() {
  const pin = await getConfig('app_pin');
  if (!pin) return;
  $('#pin-overlay').classList.remove('hidden');
  $('#app').classList.add('hidden');
}

function desbloquearApp() {
  const input = $('#pin-input').value.trim();
  getConfig('app_pin').then((pin) => {
    if (input === pin) {
      $('#pin-overlay').classList.add('hidden');
      $('#app').classList.remove('hidden');
      $('#pin-error').style.display = 'none';
      $('#pin-input').value = '';
    } else {
      $('#pin-error').style.display = 'block';
      $('#pin-input').value = '';
    }
  });
}

/* ---------- Menú / Config ---------- */
function cerrarMenu(ev) { if (ev.target === $('#menu-overlay')) $('#menu-overlay').classList.add('hidden'); }
function cerrarMenuDirecto() { $('#menu-overlay').classList.add('hidden'); }

async function mostrarConfigIAProtegido() {
  const ok = await requierePIN();
  if (ok) mostrarConfigIA();
}

async function borrarTodoProtegido() {
  const ok = await requierePIN();
  if (ok) borrarTodo();
}

function mostrarAyuda() {
  alert('Búnker de Viajes\n\n📅 Calendario mes/semana/año\n🤖 Claude IA (validación de key + protección PIN)\n🔐 Documentos cifrados + PIN de acceso\n📤 Backups JSON\n\nTodo offline. Cada dispositivo tiene sus datos aislados en IndexedDB. Si compartes móvil, usa el PIN.');
}

/* ---------- Init ---------- */
document.addEventListener('DOMContentLoaded', async () => {
  await verificarBloqueo();
  renderHome();
  $('#btn-back').addEventListener('click', irHome);
  $('#btn-menu').addEventListener('click', () => $('#menu-overlay').classList.remove('hidden'));
  $('#pin-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') desbloquearApp(); });
});
