// Small vanilla SVG chart module — no Chart.js, no runtime dependency.
// Charts are plain SVG rendered from usage data; an accessible HTML table
// mirrors the underlying values. Colors are read from CSS custom properties so
// light/dark appearance stays correct.

const NS = 'http://www.w3.org/2000/svg';

function cssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

function palette() {
  return {
    accent: cssVar('--tint', '#4f46e5'),
    success: cssVar('--success', '#1f8b4c'),
    warning: cssVar('--warning', '#b25000'),
    danger: cssVar('--danger', '#d70015'),
    grid: cssVar('--separator', 'rgba(60,60,67,0.29)'),
    text: cssVar('--fg-secondary', '#6e6e73'),
    surface: cssVar('--bg-surface', '#ffffff'),
    series: [
      cssVar('--chart-1', '#4f46e5'),
      cssVar('--chart-2', '#0d9488'),
      cssVar('--chart-3', '#d97706'),
      cssVar('--chart-4', '#db2777'),
      cssVar('--chart-5', '#7c3aed'),
      cssVar('--chart-6', '#0891b2'),
    ],
  };
}

function humanBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
}

function humanNum(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

function shortLabel(label) {
  // hour bucket "2026-01-15T14" -> "Jan 15 14:00"; day label -> "Jan 15"
  const t = label.indexOf('T');
  if (t >= 0) {
    const d = label.slice(0, t);
    const h = label.slice(t + 1);
    const dt = new Date(d + 'T' + h + ':00:00Z');
    return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' + h + ':00';
  }
  const dt = new Date(label + 'T00:00:00Z');
  return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function el(name, attrs, parent) {
  const node = document.createElementNS(NS, name);
  for (const k in attrs) node.setAttribute(k, attrs[k]);
  if (parent) parent.appendChild(node);
  return node;
}

function renderBarChart(svg, buckets, col) {
  svg.innerHTML = '';
  const w = svg.clientWidth || 600;
  const h = 240;
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');

  if (!buckets.length) {
    el('text', { x: w / 2, y: h / 2, 'text-anchor': 'middle', fill: col.text, 'font-size': 13 }, svg)
      .textContent = 'No data';
    return;
  }

  const pad = { l: 46, r: 12, t: 12, b: 34 };
  const iw = w - pad.l - pad.r;
  const ih = h - pad.t - pad.b;
  const max = Math.max(...buckets.map((b) => b.count), 1);

  // y-axis gridlines + labels (4 ticks)
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ih - (ih * i) / 4;
    el('line', { x1: pad.l, y1: y, x2: w - pad.r, y2: y, stroke: col.grid, 'stroke-width': 1 }, svg);
    el('text', { x: pad.l - 6, y: y + 4, 'text-anchor': 'end', fill: col.text, 'font-size': 10 }, svg)
      .textContent = humanNum(Math.round((max * i) / 4));
  }

  const bw = buckets.length > 1 ? Math.min(34, iw / buckets.length) * 0.7 : 34;
  const step = buckets.length > 1 ? iw / buckets.length : iw / 2;
  buckets.forEach((b, i) => {
    const bh = (b.count / max) * ih;
    const x = pad.l + (buckets.length > 1 ? step * i + (step - bw) / 2 : iw / 2 - bw / 2);
    const y = pad.t + ih - bh;
    el('rect', { x, y, width: bw, height: bh, rx: 4, fill: col.accent, opacity: 0.9 }, svg);
    el('title', {}, svg).textContent = shortLabel(b.label) + ': ' + b.count;
    // x label (throttled)
    const stride = Math.max(1, Math.ceil(buckets.length / 8));
    if (i % stride === 0) {
      el('text', { x: x + bw / 2, y: h - 10, 'text-anchor': 'middle', fill: col.text, 'font-size': 9 }, svg)
        .textContent = shortLabel(b.label);
    }
  });
}

function renderLineChart(svg, buckets, col) {
  svg.innerHTML = '';
  const w = svg.clientWidth || 600;
  const h = 240;
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');

  if (!buckets.length) {
    el('text', { x: w / 2, y: h / 2, 'text-anchor': 'middle', fill: col.text, 'font-size': 13 }, svg)
      .textContent = 'No data';
    return;
  }

  const pad = { l: 46, r: 12, t: 12, b: 34 };
  const iw = w - pad.l - pad.r;
  const ih = h - pad.t - pad.b;
  const max = Math.max(...buckets.map((b) => b.bytes), 1);
  const step = buckets.length > 1 ? iw / (buckets.length - 1) : iw / 2;

  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ih - (ih * i) / 4;
    el('line', { x1: pad.l, y1: y, x2: w - pad.r, y2: y, stroke: col.grid, 'stroke-width': 1 }, svg);
    el('text', { x: pad.l - 6, y: y + 4, 'text-anchor': 'end', fill: col.text, 'font-size': 10 }, svg)
      .textContent = humanBytes(Math.round((max * i) / 4));
  }

  const pts = buckets.map((b, i) => {
    const x = buckets.length > 1 ? pad.l + step * i : pad.l + iw / 2;
    const y = pad.t + ih - (b.bytes / max) * ih;
    return { x, y, b };
  });

  const path = pts.map((p, i) => (i === 0 ? 'M' : 'L') + p.x + ' ' + p.y).join(' ');
  const area = pts.length ? 'M' + pts[0].x + ' ' + (pad.t + ih) + ' ' + path + ' L' + pts[pts.length - 1].x + ' ' + (pad.t + ih) + ' Z' : '';

  el('path', { d: area, fill: col.success, opacity: 0.15 }, svg);
  el('path', { d: path, fill: 'none', stroke: col.success, 'stroke-width': 2 }, svg);
  pts.forEach((p) => {
    el('circle', { cx: p.x, cy: p.y, r: 2, fill: col.success }, svg);
    el('title', {}, svg).textContent = shortLabel(p.b.label) + ': ' + humanBytes(p.b.bytes);
  });

  const stride = Math.max(1, Math.ceil(buckets.length / 8));
  pts.forEach((p, i) => {
    if (i % stride === 0) {
      el('text', { x: p.x, y: h - 10, 'text-anchor': 'middle', fill: col.text, 'font-size': 9 }, svg)
        .textContent = shortLabel(p.b.label);
    }
  });
}

function renderDoughnut(svg, legend, signals, col) {
  svg.innerHTML = '';
  legend.innerHTML = '';
  const size = 200;
  svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);

  if (!signals.length || signals.every((s) => s.count <= 0)) {
    el('text', { x: size / 2, y: size / 2, 'text-anchor': 'middle', fill: col.text, 'font-size': 13 }, svg)
      .textContent = 'No data';
    return;
  }

  const total = signals.reduce((a, s) => a + s.count, 0);
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 12;
  const inner = r * 0.62;

  let angle = -Math.PI / 2;
  signals.forEach((s, i) => {
    const frac = s.count / total;
    const sweep = frac * Math.PI * 2;
    const x1 = cx + r * Math.cos(angle);
    const y1 = cy + r * Math.sin(angle);
    const x2 = cx + r * Math.cos(angle + sweep);
    const y2 = cy + r * Math.sin(angle + sweep);
    const large = sweep > Math.PI ? 1 : 0;
    const color = col.series[i % col.series.length];
    const d = `M${x1} ${y1} A${r} ${r} 0 ${large} 1 ${x2} ${y2} L${cx + inner * Math.cos(angle + sweep)} ${cy + inner * Math.sin(angle + sweep)} A${inner} ${inner} 0 ${large} 0 ${cx + inner * Math.cos(angle)} ${cy + inner * Math.sin(angle)} Z`;
    el('path', { d, fill: color }, svg);
    el('title', {}, svg).textContent = s.type + ': ' + humanNum(s.count);

    // legend
    const li = document.createElement('span');
    li.className = 'chart-legend-item';
    const dot = document.createElement('span');
    dot.className = 'chart-legend-swatch';
    dot.style.background = color;
    li.appendChild(dot);
    li.appendChild(document.createTextNode(s.type + ' · ' + humanNum(s.count)));
    legend.appendChild(li);

    angle += sweep;
  });
}

function renderStats(data) {
  const reqTotal = (data.requests || []).reduce((a, r) => a + (r.count || 0), 0);
  const volTotal = (data.volumes || []).reduce((a, v) => a + (v.bytes || 0), 0);
  const sigCount = (data.signal_types || []).filter((s) => s.count > 0).length;
  setText('stat-requests', humanNum(reqTotal));
  setText('stat-volume', humanBytes(volTotal));
  setText('stat-signals', sigCount ? String(sigCount) : '0');
}

function setText(id, text) {
  const n = document.getElementById(id);
  if (n) n.textContent = text;
}

function renderTable(data) {
  const body = document.getElementById('chart-table-body');
  if (!body) return;
  body.innerHTML = '';

  const req = data.requests || [];
  const vol = data.volumes || [];
  const sig = data.signal_types || [];

  const table = document.createElement('table');
  table.className = 'data-table';
  let html = '<thead><tr><th scope="col">Period</th><th scope="col">Requests</th><th scope="col">Volume</th></tr></thead><tbody>';
  const volByLabel = {};
  vol.forEach((v) => { volByLabel[v.label] = v.bytes; });
  const rows = req.length ? req : vol.map((v) => ({ label: v.label, count: 0 }));
  rows.forEach((r) => {
    html += '<tr><th scope="row">' + shortLabel(r.label) + '</th><td>' + humanNum(r.count || 0) +
      '</td><td>' + humanBytes(volByLabel[r.label] || 0) + '</td></tr>';
  });
  if (sig.length) {
    html += '<tr><th scope="row" colspan="3">Signal breakdown</th></tr>';
    sig.forEach((s) => {
      html += '<tr><th scope="row">' + s.type + '</th><td colspan="2">' + humanNum(s.count) + ' requests</td></tr>';
    });
  }
  html += '</tbody>';
  table.innerHTML = html;
  body.appendChild(table);
}

function render(data) {
  const col = palette();
  renderStats(data);
  renderBarChart(document.getElementById('requestsChart'), data.requests || [], col);
  renderLineChart(document.getElementById('volumesChart'), data.volumes || [], col);
  renderDoughnut(document.getElementById('signalsChart'), document.getElementById('signalsLegend'), data.signal_types || [], col);
  renderTable(data);
}

export function loadUsage(tenantId) {
  let currentRange = '7d';
  let lastData = null;

  function selectRange(range, btn) {
    currentRange = range;
    document.querySelectorAll('.segmented button').forEach((b) => {
      const active = b.getAttribute('data-range') === range;
      b.classList.toggle('is-active', active);
      b.setAttribute('aria-pressed', active ? 'true' : 'false');
    });
    fetchData();
  }

  async function fetchData() {
    try {
      const resp = await fetch('/tenants/' + tenantId + '/usage/data?range=' + currentRange, { headers: { 'Accept': 'application/json' } });
      if (!resp.ok) throw new Error('load failed');
      lastData = await resp.json();
      render(lastData);
    } catch (err) {
      setText('stat-requests', '—');
      setText('stat-volume', '—');
      setText('stat-signals', '—');
    }
  }

  document.querySelectorAll('.segmented button').forEach((btn) => {
    btn.addEventListener('click', () => selectRange(btn.getAttribute('data-range'), btn));
  });

  const schemeMQ = window.matchMedia('(prefers-color-scheme: dark)');
  const onScheme = () => { if (lastData) render(lastData); };
  if (schemeMQ.addEventListener) schemeMQ.addEventListener('change', onScheme);
  else if (schemeMQ.addListener) schemeMQ.addListener(onScheme);

  window.addEventListener('resize', () => { if (lastData) render(lastData); });

  fetchData();
}
