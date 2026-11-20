<style>
#ipscan .ipscan-form { display: flex; flex-wrap: wrap; gap: .75rem; align-items: flex-end; margin-bottom: 1rem; }
#ipscan .ipscan-form label { display: flex; flex-direction: column; font-size: .85rem; gap: .2rem; }
#ipscan .ipscan-form input, #ipscan .ipscan-form select { min-width: 9rem; }
#ipscan .ipscan-progress { height: 6px; background: rgba(128,128,128,.25); border-radius: 3px; overflow: hidden; margin: .5rem 0 1rem; }
#ipscan .ipscan-progress > div { height: 100%; width: 0; background: var(--bs-primary, #0d6efd); transition: width .3s; }
#ipscan table td, #ipscan table th { white-space: nowrap; vertical-align: middle; }
#ipscan table td.ipscan-details { white-space: normal; max-width: 22rem; }
#ipscan th[data-sort] { cursor: pointer; user-select: none; }
#ipscan th[data-sort].asc::after { content: " \25B2"; font-size: .7em; }
#ipscan th[data-sort].desc::after { content: " \25BC"; font-size: .7em; }
#ipscan .ipscan-type { font-size: .8rem; }
</style>

<div id="ipscan" class="container-fluid">
  <h2>IP Scanner</h2>
  <p class="text-muted">Scans a range of addresses and lists everything that answers, including FPP, WLED, Falcon and other show controllers.</p>

  <div class="ipscan-form">
    <label>Network
      <select id="ipscanNet" class="form-select form-select-sm"></select>
    </label>
    <label>Start IP
      <input id="ipscanStart" class="form-control form-control-sm" placeholder="192.168.1.1">
    </label>
    <label>End IP
      <input id="ipscanEnd" class="form-control form-control-sm" placeholder="192.168.1.254">
    </label>
    <label>TCP ports
      <input id="ipscanPorts" class="form-control form-control-sm" value="22,80,443,4048,8080">
    </label>
    <label>Timeout (s)
      <input id="ipscanTimeout" type="number" step="0.1" min="0.2" max="5" value="1" class="form-control form-control-sm" style="min-width:5rem">
    </label>
    <label class="form-check-label" style="flex-direction:row;align-items:center;gap:.4rem">
      <input id="ipscanDns" type="checkbox" class="form-check-input" checked> Hostnames
    </label>
    <button id="ipscanGo" class="buttons btn-success">Scan</button>
    <button id="ipscanStop" class="buttons btn-danger" style="display:none">Stop</button>
    <a id="ipscanCsv" class="buttons" href="api/plugin/fpp-plugin-ipscan/results.csv">Download CSV</a>
  </div>

  <div class="d-flex gap-3 align-items-center flex-wrap">
    <strong id="ipscanSummary">No scan yet.</strong>
    <input id="ipscanFilter" class="form-control form-control-sm" style="max-width:16rem" placeholder="Filter results">
    <label class="form-check-label"><input id="ipscanLightingOnly" type="checkbox" class="form-check-input"> Only lighting controllers</label>
  </div>
  <div class="ipscan-progress"><div id="ipscanBar"></div></div>

  <div class="table-responsive">
    <table class="table table-sm table-striped table-hover">
      <thead><tr>
        <th data-sort="ip">IP</th>
        <th data-sort="ping_ms">Ping</th>
        <th data-sort="hostname">Hostname</th>
        <th data-sort="device_type">Type</th>
        <th data-sort="device_name">Name</th>
        <th data-sort="version">Version</th>
        <th data-sort="mac">MAC</th>
        <th data-sort="vendor">Vendor</th>
        <th data-sort="open_ports">Ports</th>
        <th>Details</th>
      </tr></thead>
      <tbody id="ipscanRows"></tbody>
    </table>
  </div>
</div>

<script>
(function () {
  var API = 'api/plugin/fpp-plugin-ipscan/';
  var LIGHTING = ['FPP', 'WLED', 'Falcon Controller', 'ESPixelStick', 'Kulp Controller', 'Genius Controller',
                  'HinksPix', 'SanDevices', 'AlphaPix', 'Experience Lights', 'PixLite'];
  var hosts = [], sortKey = 'ip', sortDir = 1, timer = null;

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
    });
  }
  function ipNum(ip) { return ip.split('.').reduce(function (a, o) { return a * 256 + (+o); }, 0); }

  function link(h) {
    var ports = String(h.open_ports || '').split(' ');
    if (ports.indexOf('80') >= 0) return 'http://' + h.ip + '/';
    if (ports.indexOf('8080') >= 0) return 'http://' + h.ip + ':8080/';
    if (ports.indexOf('443') >= 0) return 'https://' + h.ip + '/';
    return null;
  }

  function render() {
    var f = $('ipscanFilter').value.toLowerCase();
    var only = $('ipscanLightingOnly').checked;
    var rows = hosts.filter(function (h) {
      if (only && LIGHTING.indexOf(h.device_type) < 0) return false;
      if (!f) return true;
      return [h.ip, h.hostname, h.device_type, h.device_name, h.mac, h.vendor, h.details, h.version]
        .join(' ').toLowerCase().indexOf(f) >= 0;
    });
    rows.sort(function (a, b) {
      var x = a[sortKey], y = b[sortKey];
      if (sortKey === 'ip') { x = ipNum(a.ip); y = ipNum(b.ip); }
      else if (sortKey === 'ping_ms') { x = x === '' ? 1e9 : +x; y = y === '' ? 1e9 : +y; }
      else { x = String(x || '').toLowerCase(); y = String(y || '').toLowerCase(); }
      return (x < y ? -1 : x > y ? 1 : 0) * sortDir;
    });
    $('ipscanRows').innerHTML = rows.map(function (h) {
      var url = link(h);
      var ip = url ? '<a href="' + esc(url) + '" target="_blank">' + esc(h.ip) + '</a>' : esc(h.ip);
      var type = h.device_type ? '<span class="badge ' +
        (LIGHTING.indexOf(h.device_type) >= 0 ? 'bg-success' : 'bg-secondary') +
        ' ipscan-type">' + esc(h.device_type) + '</span>' : '';
      return '<tr><td>' + ip + '</td><td>' + esc(h.ping_ms) + '</td><td>' + esc(h.hostname) +
        '</td><td>' + type + '</td><td>' + esc(h.device_name) + '</td><td>' + esc(h.version) +
        '</td><td><code>' + esc(h.mac) + '</code></td><td>' + esc(h.vendor) + '</td><td>' +
        esc(h.open_ports) + '</td><td class="ipscan-details">' + esc(h.details) + '</td></tr>';
    }).join('');
  }

  function show(st) {
    hosts = st.hosts || [];
    var pct = st.total ? Math.round(100 * st.done / st.total) : 0;
    $('ipscanBar').style.width = (st.state === 'idle' ? 0 : pct) + '%';
    var running = st.state === 'running';
    $('ipscanGo').style.display = running ? 'none' : '';
    $('ipscanStop').style.display = running ? '' : 'none';
    if (st.state === 'idle') {
      $('ipscanSummary').textContent = 'No scan yet.';
    } else {
      var when = st.finished ? new Date(st.finished * 1000).toLocaleString() : '';
      var secs = st.started ? (((st.finished || Date.now() / 1000) - st.started)).toFixed(1) : '';
      $('ipscanSummary').textContent = (running ? 'Scanning ' : (st.state === 'stopped' ? 'Stopped: ' : 'Finished: ')) +
        (st.range || '') + ' — ' + st.done + '/' + st.total + ' scanned, ' + st.alive + ' alive' +
        (secs ? ' in ' + secs + 's' : '') + (when ? ' (' + when + ')' : '');
    }
    render();
    clearTimeout(timer);
    if (running) timer = setTimeout(poll, 1000);
  }

  function poll() { $.get(API + 'status').done(show); }

  $('ipscanGo').addEventListener('click', function () {
    var body = {
      start: $('ipscanStart').value.trim(),
      end: $('ipscanEnd').value.trim(),
      ports: $('ipscanPorts').value.trim(),
      timeout: parseFloat($('ipscanTimeout').value) || 1,
      dns: $('ipscanDns').checked
    };
    $.ajax({ url: API + 'scan', type: 'POST', contentType: 'application/json', data: JSON.stringify(body) })
      .done(function () { poll(); })
      .fail(function (x) {
        var msg = (x.responseJSON && x.responseJSON.message) || x.statusText;
        $.jGrowl ? $.jGrowl('Scan failed: ' + msg, { themeState: 'danger' }) : alert('Scan failed: ' + msg);
      });
  });
  $('ipscanStop').addEventListener('click', function () { $.post(API + 'stop').done(poll); });
  $('ipscanFilter').addEventListener('input', render);
  $('ipscanLightingOnly').addEventListener('change', render);
  $('ipscanNet').addEventListener('change', function () {
    var o = this.options[this.selectedIndex];
    if (o && o.dataset.start) { $('ipscanStart').value = o.dataset.start; $('ipscanEnd').value = o.dataset.end; }
  });
  document.querySelectorAll('#ipscan th[data-sort]').forEach(function (th) {
    th.addEventListener('click', function () {
      var k = th.getAttribute('data-sort');
      sortDir = (k === sortKey) ? -sortDir : 1;
      sortKey = k;
      document.querySelectorAll('#ipscan th[data-sort]').forEach(function (t) { t.classList.remove('asc', 'desc'); });
      th.classList.add(sortDir > 0 ? 'asc' : 'desc');
      render();
    });
  });

  function fillNetworks(nets) {
    var sel = $('ipscanNet');
    sel.innerHTML = '';
    nets.forEach(function (n) {
      var o = document.createElement('option');
      o.textContent = n.interface + ' (' + n.address + ')';
      o.dataset.start = n.start; o.dataset.end = n.end;
      sel.appendChild(o);
    });
    var custom = document.createElement('option');
    custom.textContent = 'Custom';
    sel.appendChild(custom);
    if (nets.length && !$('ipscanStart').value) {
      $('ipscanStart').value = nets[0].start;
      $('ipscanEnd').value = nets[0].end;
    }
  }
  fillNetworks([]);
  $.get(API + 'defaults')
    .done(function (d) { fillNetworks((d && d.networks) || []); })
    .fail(function (x) {
      console.error('ipscan: could not load networks', x.status, x.responseText);
    });
  poll();
})();
</script>
