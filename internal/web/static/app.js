    function basePath() {
      const pathname = window.location.pathname || '/';
      const loginIndex = pathname.indexOf('/login');
      if (loginIndex >= 0) return pathname.slice(0, loginIndex);
      if (pathname === '/') return '';
      return pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
    }
    function apiPath(path) { return basePath() + path; }
    function panelPath(path) { return basePath() + path; }

    function handleSessionExpired(response) {
      if (!response || response.status !== 401) return false;
      showToast('登录状态已过期，请重新登录', 'error');
      setTimeout(function() { window.location.href = panelPath('/login'); }, 600);
      return true;
    }

    const nativeFetch = window.fetch.bind(window);
    window.fetch = async function(input, init) {
      const response = await nativeFetch(input, init);
      const url = String(input && input.url ? input.url : input);
      if (url.includes('/api/') && !url.includes('/api/login') && !url.includes('/api/session')) {
        handleSessionExpired(response);
      }
      return response;
    };

    async function apiFetch(path, options) {
      return fetch(apiPath(path), options || {});
    }

    const inboundList = document.getElementById('inbound-list');
    const inboundCount = document.getElementById('inbound-count');
    const clientCount = document.getElementById('client-count');
    const totalTraffic = document.getElementById('total-traffic');
    const xrayStatusMetric = document.getElementById('xray-status-metric');

    function renderInbounds(inbounds) {
      window._cachedInbounds = inbounds;  // cache for port conflict check
      inboundCount.textContent = String(inbounds.length);
      const allClients = inbounds.flatMap(i => i.clients || []);
      clientCount.textContent = String(allClients.length);
      // Compute total traffic
      const totalUp = allClients.reduce((s, c) => s + (c.up || 0), 0);
      const totalDown = allClients.reduce((s, c) => s + (c.down || 0), 0);
      totalTraffic.textContent = formatBytes(totalUp + totalDown);
      // Active clients (enabled + not expired + not over limit)
      const now = Math.floor(Date.now() / 1000);
      const active = allClients.filter(c => {
        if (!c.enabled) return false;
        if (c.expiry_at && c.expiry_at > 0 && c.expiry_at <= now) return false;
        if (c.traffic_limit && c.traffic_limit > 0 && (c.up||0)+(c.down||0) >= c.traffic_limit) return false;
        return true;
      }).length;
      // Show active/total in client count description
      const card = clientCount.closest('.card');
      const p = card ? card.querySelector('p') : null;
      if (p) p.textContent = active + ' / ' + allClients.length;
      renderOverviewInsights(inbounds, allClients, active);
      updateProtocolBreakdown(inbounds);
      if (inbounds.length === 0) {
        inboundList.className = 'list';
        inboundList.innerHTML = renderEmptyState('暂无入站', '先创建一个 VLESS / VMess / Trojan / Shadowsocks 节点；MiGate 会自动生成客户端与 Xray 配置。', [
          {label:'创建入站', onclick:"openCreateInbound()"},
          {label:'查看 Xray', onclick:"navigateTo('xray')", secondary:true},
          {label:'查看 Sing-box', onclick:"navigateTo('singbox')", secondary:true}
        ]);
        return;
      }
      inboundList.className = 'list';
      inboundList.innerHTML = inbounds.map((inbound) => {
        const enabledClass = inbound.enabled ? 'enabled' : 'disabled';
        const enabledText = inbound.enabled ? 'Enabled' : 'Disabled';
        return '<div class="resource-row">' +
          '<div class="resource-main">' +
            '<div class="resource-title"><strong>' + escapeHtml(inbound.remark || '-') + '</strong><span class="status-badge ' + enabledClass + '">' + enabledText + '</span></div>' +
            '<div class="resource-meta"><span>' + escapeHtml(inbound.protocol) + '</span><span>:' + inbound.port + '</span><span>' + escapeHtml(inbound.network || 'tcp') + ' / ' + escapeHtml(inbound.security || 'none') + '</span><span>' + ((inbound.clients || []).length) + ' 客户端</span></div>' +
          '</div>' +
          '<div class="resource-actions">' +
            '<button class="icon-btn" onclick="toggleClientSection(' + inbound.id + ')" title="展开客户端">' + ((inbound.clients || []).length) + 'C</button>' +
            '<button class="icon-btn" onclick="editInbound(' + inbound.id + ')" title="编辑">Edit</button>' +
            '<button class="icon-btn" onclick="toggleInbound(' + inbound.id + ')" title="启用/禁用">' + (inbound.enabled ? 'ON' : 'OFF') + '</button>' +
            '<button class="danger-icon-btn" onclick="deleteInbound(' + inbound.id + ')" title="删除">DEL</button>' +
          '</div>' +
        '</div>' +
        '<div id="client-section-' + inbound.id + '" class="client-subsection" style="display:none"></div>';
      }).join('');
    }

    function filterInbounds() { applyInboundFilterSort(); }
    function sortInbounds() { applyInboundFilterSort(); }
    function applyInboundFilterSort() {
      const q = (document.getElementById('inbound-search').value || '').toLowerCase();
      const sortBy = (document.getElementById('inbound-sort').value || 'id');
      let list = (window._cachedInbounds || []).slice();
      if (q) {
        list = list.filter(ib =>
          (ib.remark || '').toLowerCase().includes(q) ||
          (ib.protocol || '').toLowerCase().includes(q) ||
          String(ib.port).includes(q) ||
          (ib.network || '').toLowerCase().includes(q)
        );
      }
      list.sort((a, b) => {
        if (sortBy === 'port') return a.port - b.port;
        if (sortBy === 'protocol') return (a.protocol || '').localeCompare(b.protocol || '');
        if (sortBy === 'clients') return (b.clients || []).length - (a.clients || []).length;
        return a.id - b.id;
      });
      renderInbounds(window._cachedInbounds);  // re-render full list (stats etc.)
      // Now filter the DOM rows
      const allowedIds = new Set(list.map(ib => ib.id));
      const rows = inboundList.querySelectorAll('.resource-row');
      if (rows.length > 0 && allowedIds.size === 0) {
        inboundList.innerHTML = '<div class="empty-state"><div class="empty-state-title">无匹配结果</div><div class="empty-state-copy">没有入站匹配当前的搜索或筛选条件。</div></div>';
        return;
      }
      rows.forEach(row => {
        const idMatch = row.querySelector('[onclick*="editInbound"]');
        if (idMatch) {
          const m = idMatch.getAttribute('onclick').match(/editInbound\((\d+)\)/);
          if (m) row.style.display = allowedIds.has(Number(m[1])) ? '' : 'none';
        }
      });
      // Also hide/show client subsections
      const subs = inboundList.querySelectorAll('.client-subsection');
      subs.forEach(el => {
        const m = el.id.match(/client-section-(\d+)/);
        if (m) el.style.display = (!allowedIds.has(Number(m[1])) || el.style.display === 'none') ? 'none' : el.style.display;
      });
      // Reorder rows to match sort order
      const allEls = Array.from(inboundList.children);
      const orderMap = {};
      list.forEach((ib, i) => orderMap[ib.id] = i);
      allEls.sort((a, b) => {
        const mA = a.id ? a.id.match(/client-section-(\d+)/) : null;
        const mB = b.id ? b.id.match(/client-section-(\d+)/) : null;
        const idA = mA ? Number(mA[1]) : (a.querySelector('[onclick*="editInbound"]')?.getAttribute('onclick')?.match(/editInbound\((\d+)\)/)?.[1] || 9999);
        const idB = mB ? Number(mB[1]) : (b.querySelector('[onclick*="editInbound"]')?.getAttribute('onclick')?.match(/editInbound\((\d+)\)/)?.[1] || 9999);
        return (orderMap[idA] ?? 9999) - (orderMap[idB] ?? 9999);
      });
      allEls.forEach(el => inboundList.appendChild(el));
    }

    function renderOverviewInsights(inbounds, allClients, active) {
      const health = document.getElementById('overview-health-summary');
      const activeSummary = document.getElementById('overview-active-summary');
      const enabledInbounds = inbounds.filter(i => i.enabled).length;
      const disabledInbounds = inbounds.length - enabledInbounds;
      const limitedClients = allClients.filter(c => {
        const used = (c.up || 0) + (c.down || 0);
        return (c.traffic_limit || 0) > 0 && used >= c.traffic_limit;
      }).length;
      const expiredClients = allClients.filter(c => c.expiry_at && c.expiry_at > 0 && c.expiry_at <= Math.floor(Date.now() / 1000)).length;
      if (health) {
        health.textContent = inbounds.length === 0
          ? '还没有入站。建议先创建一个 VLESS/REALITY 或 TLS 入站，再添加客户端。'
          : '已启用 ' + enabledInbounds + ' 个入站，停用 ' + disabledInbounds + ' 个；受限客户端 ' + limitedClients + ' 个，过期客户端 ' + expiredClients + ' 个。';
      }
      if (activeSummary) {
        activeSummary.textContent = '活跃客户端 ' + active + ' / ' + allClients.length;
      }
    }

    function updateProtocolBreakdown(inbounds) {
      const el = document.getElementById('overview-protocol-breakdown');
      if (!el) return;
      const protocols = ['vless', 'vmess', 'trojan', 'shadowsocks'];
      const labels = {vless:'VLESS', vmess:'VMess', trojan:'Trojan', shadowsocks:'Shadowsocks'};
      const counts = protocols.reduce((acc, proto) => {
        acc[proto] = inbounds.filter(i => (i.protocol || '').toLowerCase() === proto).length;
        return acc;
      }, {});
      el.innerHTML = protocols.map(proto =>
        '<div class="protocol-breakdown-row"><span>' + labels[proto] + '</span><strong>' + counts[proto] + '</strong></div>'
      ).join('');
    }

    function escapeHtml(value) {
      return String(value || '').replace(/[&<>"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[char]));
    }
    function escHtml(value) { return escapeHtml(value); }

    function escapeJsString(value) {
      return escapeHtml(String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\&quot;').replace(/'/g, "\\&#39;").replace(/\n/g, '\\n').replace(/\r/g, ''));
    }

    function renderEmptyState(title, copy, actions) {
      const actionHtml = (actions || []).map((action) => {
        const cls = action.secondary ? ' class="secondary"' : '';
        return '<button' + cls + ' onclick="' + action.onclick + '">' + escapeHtml(action.label) + '</button>';
      }).join('');
      return '<div class="empty-state">' +
        '<div class="empty-state-title">' + escapeHtml(title) + '</div>' +
        '<div class="empty-state-copy">' + escapeHtml(copy) + '</div>' +
        (actionHtml ? '<div class="empty-state-actions">' + actionHtml + '</div>' : '') +
      '</div>';
    }

    function renderNotice(title, copy, type) {
      const cls = type ? ' ' + type : '';
      return '<div class="notice' + cls + '">' +
        '<div class="notice-title">' + escapeHtml(title) + '</div>' +
        '<div class="notice-copy">' + escapeHtml(copy || '') + '</div>' +
      '</div>';
    }

    async function loadInbounds() {
      try {
        const response = await fetch(apiPath('/api/inbounds'));
        if (!response.ok) { console.error('loadInbounds: API error', response.status); return; }
        const data = await response.json();
        renderInbounds(data.inbounds || []);
        loadOverviewServiceStatuses();
      } catch(e) {
        console.error('loadInbounds error:', e);
      }
    }

    function formatServiceStatus(service) {
      if (!service) return '无法连接';
      if (service.installed === false) return '未安装';
      if (service.status === 'running' || service.status === 'active') return '运行中';
      if (service.status === 'stopped' || service.status === 'inactive') return '已停止';
      return service.status || '未知';
    }

    async function loadOverviewServiceStatuses() {
      try {
        const xr = await fetch(apiPath('/api/xray/status'));
        if (!xr.ok) throw new Error('xray status ' + xr.status);
        const xs = await xr.json();
        xrayStatusMetric.textContent = formatServiceStatus(xs);
      } catch (e) {
        xrayStatusMetric.textContent = '无法连接';
      }
      try {
        const sr = await fetch(apiPath('/api/singbox/status'));
        if (!sr.ok) throw new Error('singbox status ' + sr.status);
        const ss = await sr.json();
        document.getElementById('singbox-status-metric').textContent = formatServiceStatus(ss);
      } catch (e) {
        document.getElementById('singbox-status-metric').textContent = '无法连接';
      }
    }

    var outbounds = [];

    function isCustomSpeedTestOutbound(ob) {
      if (!ob) return false;
      return ob.enabled !== false &&
        !['direct','blocked'].includes(ob.tag) &&
        !['freedom','blackhole'].includes(ob.protocol) &&
        !!ob.address;
    }

    async function loadOutbounds() {
      const el = document.getElementById('outbound-list');
      if (!el) return;
      try {
        const resp = await fetch(apiPath('/api/outbounds'));
        if (!resp.ok) { el.innerHTML = '<div class=\"muted\" style=\"padding:12px\">加载失败</div>'; return; }
        const data = await resp.json();
        outbounds = Array.isArray(data) ? data : (data.outbounds || []);
        if (!outbounds.length) {
          el.innerHTML = renderEmptyState('暂无出站', '出站用于链式代理转发。点击上方"新建出站"添加 SOCKS5 / HTTP 代理。');
          return;
        }
        el.innerHTML = '<div style="display:grid;grid-template-columns:1fr;gap:8px" id="outbound-drag-container">' +
          outbounds.map(ob => renderOutboundCard(ob)).join('') +
          '</div>';
        setTimeout(attachOutboundDragHandlers, 0);
      } catch(e) {
        el.innerHTML = '<div class=\"muted\" style=\"padding:12px\">加载失败</div>';
      }
    }

    function renderOutboundCard(ob) {
      const protoLabel = ob.protocol === 'freedom' ? '直接连接' :
        ob.protocol === 'blackhole' ? '阻断' :
        ob.protocol.toUpperCase();
      const detail = ob.address ? ob.address + ':' + ob.port : '';
      const editable = ob.protocol !== 'freedom' && ob.protocol !== 'blackhole';
      const enabledColor = ob.enabled ? 'var(--green)' : 'var(--muted)';
      const pinned = ob.sort === 0 || ob.sort === 1;
      const isDraggable = editable && !pinned;
      return '<div class=\"card\" style=\"padding:12px 16px;display:flex;align-items:center;gap:12px\"' +
        (isDraggable ? ' draggable=\"true\" data-ob-id=\"' + ob.id + '\"' : '') + '>' +
        '<span style=\"color:' + enabledColor + ';font-size:18px\">' + (ob.enabled ? '&#9679;' : '&#9678;') + '</span>' +
        '<div style=\"flex:1;min-width:0\">' +
        '<div style=\"font-weight:600;font-size:var(--text-sm)\">' + escHtml(ob.remark||ob.tag) + '</div>' +
        '<div class=\"muted\" style=\"font-size:var(--text-xs)\">' + escHtml(ob.tag) + ' &middot; ' + protoLabel + (detail ? ' &middot; ' + escHtml(detail) : '') + ' <span id=\"ping-' + ob.id + '\"></span></div>' +
        '</div><div style=\"display:flex;gap:6px\">' +
        (editable ? '<button class=\"icon-btn\" onclick=\"speedTestOutbound(' + ob.id + ')\" title=\"测速\">&#9889;</button>' +
          '<button class=\"icon-btn\" onclick=\"openEditOutbound(' + ob.id + ')\" title=\"编辑\">&#9998;</button>' +
          '<button class=\"danger-icon-btn\" onclick=\"deleteOutbound(' + ob.id + ')\" title=\"删除\">&#10005;</button>' :
        '<span class=\"muted\" style=\"font-size:var(--text-xs);padding:4px 8px\">内置</span>') +
        '</div></div>';
    }

    function speedTestOutbound(id) {
      const el = document.getElementById('ping-' + id);
      if (!el) return;
      el.textContent = '测速中...';
      fetch(apiPath('/api/outbounds/' + id + '/ping')).then(function(r) { return r.json(); }).then(function(data) {
        if (data.latency >= 0) {
          el.textContent = ' ' + data.latency + 'ms';
          el.style.color = data.latency < 200 ? 'var(--green)' : data.latency < 500 ? 'var(--accent2)' : 'var(--danger)';
        } else {
          el.textContent = ' 超时';
          el.style.color = 'var(--danger)';
        }
      }).catch(function() {
        el.textContent = ' 失败';
        el.style.color = 'var(--danger)';
      });
    }

    async function batchSpeedTest() {
      var btn = document.querySelector('[onclick*=\"batchSpeedTest\"]');
      if (btn) btn.disabled = true;
      var targets = outbounds.filter(isCustomSpeedTestOutbound);
      if (!targets.length) {
        showToast('没有可测速的自定义出站', 'error');
        if (btn) btn.disabled = false;
        return;
      }
      targets.forEach(function(ob) {
        var el = document.getElementById('ping-' + ob.id);
        if (!el) return;
        el.textContent = ' 测速中';
        el.style.color = 'var(--text)';
      });
      try {
        var resp = await fetch(apiPath('/api/outbounds/speedtest-all'), {method:'POST'});
        if (!resp.ok) { showToast('测速失败', 'error'); return; }
        var results = await resp.json();
        var okCount = 0, failCount = 0;
        Object.keys(results).forEach(function(id) {
          var r = results[id];
          var el = document.getElementById('ping-' + id);
          if (!el) return;
          if (r.latency >= 0) {
            var ms = Number(r.latency).toFixed(0);
            el.textContent = ' ' + ms + 'ms';
            el.style.color = ms < 200 ? 'var(--green)' : (ms < 500 ? 'orange' : 'var(--danger)');
            okCount++;
          } else {
            el.textContent = ' 失败';
            el.style.color = 'var(--danger)';
            failCount++;
          }
        });
        showToast('完成: ' + okCount + ' 成功, ' + failCount + ' 失败', okCount > 0 ? 'success' : 'error');
      } catch(e) {
        showToast('测速异常: ' + e.message, 'error');
      } finally {
        if (btn) btn.disabled = false;
      }
    }

    function attachOutboundDragHandlers() {
      var container = document.getElementById('outbound-drag-container');
      if (!container) return;
      var draggedEl = null;
      container.addEventListener('dragstart', function(e) {
        var card = e.target.closest('[draggable]');
        if (!card) return;
        draggedEl = card;
        e.dataTransfer.effectAllowed = 'move';
        card.style.opacity = '0.4';
      });
      container.addEventListener('dragend', function(e) {
        var card = e.target.closest('[draggable]');
        if (card) card.style.opacity = '';
      });
      container.addEventListener('dragover', function(e) {
        var card = e.target.closest('[draggable]');
        if (!card || card === draggedEl || !draggedEl) return;
        e.preventDefault();
        var rect = card.getBoundingClientRect();
        var mid = rect.top + rect.height / 2;
        if (e.clientY < mid) {
          container.insertBefore(draggedEl, card);
        } else {
          container.insertBefore(draggedEl, card.nextSibling);
        }
      });
      container.addEventListener('drop', function(e) {
        e.preventDefault();
        if (!draggedEl) return;
        var ids = [];
        container.querySelectorAll('[data-ob-id]').forEach(function(el) {
          ids.push(parseInt(el.getAttribute('data-ob-id')));
        });
        if (!ids.length) return;
        fetch(apiPath('/api/outbounds/reorder'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ids: ids})
        }).then(async function(resp) {
          if (!resp.ok) { showToast('排序保存失败', 'error'); await loadOutbounds(); return; }
          showToast('排序已保存', 'success');
        }).catch(function() { showToast('排序保存失败', 'error'); loadOutbounds(); });
      });
    }

    function showModal(id) {
      var el = document.getElementById(id);
      if (el) {
        el.classList.remove('hidden');
        el.style.display = 'flex';
      }
    }
    function closeModal() {
      document.querySelectorAll('.modal-overlay').forEach(function(el) {
        el.style.display = 'none';
        el.classList.add('hidden');
      });
    }

    let socks5PoolState = {regions: [], proxies: [], selected: null};

    function openSocks5PoolDialog() {
      socks5PoolState = {regions: [], proxies: [], selected: null};
      const list = document.getElementById('socks5-pool-list');
      if (list) list.textContent = '正在加载地址池并测速...';
      showModal('socks5-pool-dialog');
      loadSocks5Pool();
    }

    function socks5ContinentForRegion(code) {
      const c = String(code || '').toUpperCase();
      const groups = {
        '北美 / NA': ['US','CA','MX'],
        '亚洲 / AS': ['HK','TW','JP','KR','SG','VN','BD','IN','ID','TH','MY','PH','CN'],
        '欧洲 / EU': ['GB','DE','FR','NL','RU','UA','PL','IT','ES','SE','FI','NO','CH'],
        '南美 / SA': ['BR','AR','CL','CO','PE'],
        '大洋洲 / OC': ['AU','NZ'],
        '非洲 / AF': ['ZA','EG','NG','KE']
      };
      for (const name in groups) {
        if (groups[name].includes(c)) return name;
      }
      return '其他 / OT';
    }

    function groupSocks5RegionsByContinent(regions) {
      const grouped = {};
      (regions || []).forEach(function(r) {
        const key = socks5ContinentForRegion(r.code);
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push(r);
      });
      Object.keys(grouped).forEach(function(key) {
        grouped[key].sort(function(a,b) { return (b.count || 0) - (a.count || 0); });
      });
      return grouped;
    }

    function renderSocks5RegionOptions(regions) {
      const grouped = groupSocks5RegionsByContinent(regions);
      const order = ['北美 / NA','亚洲 / AS','欧洲 / EU','南美 / SA','大洋洲 / OC','非洲 / AF','其他 / OT'];
      let html = '<option value="">-- 请选择地区 --</option>';
      order.forEach(function(group) {
        if (!grouped[group] || !grouped[group].length) return;
        html += '<optgroup label="🌎 ' + escapeHtml(group) + '">';
        html += grouped[group].map(function(r) {
          const code = r.code || '未知';
          const label = code + ' ' + (r.name || '') + '(' + (r.count || 0) + ')';
          return '<option value="' + escapeHtml(code) + '">' + escapeHtml(label) + '</option>';
        }).join('');
        html += '</optgroup>';
      });
      return html;
    }

    function sortSocks5PoolProxies(proxies) {
      return (proxies || []).slice().sort(function(a,b) {
        const al = Number(a.latency), bl = Number(b.latency);
        const ao = al >= 0, bo = bl >= 0;
        if (ao !== bo) return ao ? -1 : 1;
        if (ao && al !== bl) return al - bl;
        return String(a.city || a.address).localeCompare(String(b.city || b.address));
      });
    }

    function formatSocks5ProxyLine(p) {
      const latency = Number(p.latency);
      const status = latency >= 0 ? '✅ [' + latency.toFixed(0) + 'ms]' : '⏳ [验证中]';
      const city = p.city || p.country_code || p.address;
      const asn = p.asn ? 'AS' + String(p.asn).replace(/^AS/i, '') : 'AS-';
      const org = p.organization || 'Unknown';
      return status + city + ',' + asn + ',' + org;
    }

    async function loadSocks5Pool() {
      const regionSelect = document.getElementById('socks5-pool-region');
      const list = document.getElementById('socks5-pool-list');
      const country = regionSelect ? (regionSelect.value || '') : '';
      if (list) list.textContent = '正在加载并测速...';
      try {
        const resp = await apiFetch('/api/outbounds/socks5-pool?country=' + encodeURIComponent(country));
        if (!resp.ok) throw new Error('pool api ' + resp.status);
        const data = await resp.json();
        if (data.cache_status && data.cache_status !== 'hit') {
          showToast('SOCKS5 地址池缓存状态：' + data.cache_status, 'success');
        }
        socks5PoolState.regions = data.regions || [];
        socks5PoolState.proxies = sortSocks5PoolProxies(data.proxies || []);
        socks5PoolState.selected = socks5PoolState.proxies[0] || null;
        if (regionSelect && regionSelect.options.length <= 1) {
          regionSelect.innerHTML = renderSocks5RegionOptions(socks5PoolState.regions);
        }
        renderSocks5PoolList();
        renderSocks5PoolMap();
      } catch(e) {
        if (list) list.innerHTML = '<div class="empty-state"><div class="empty-state-title">地址池加载失败</div><div class="empty-state-copy">' + escapeHtml(e.message) + '</div></div>';
        renderSocks5PoolMap();
      }
    }

    function renderSocks5PoolList() {
      const list = document.getElementById('socks5-pool-list');
      if (!list) return;
      const proxies = socks5PoolState.proxies || [];
      if (!proxies.length) {
        list.innerHTML = '<div class="empty-state"><div class="empty-state-title">暂无可用代理</div><div class="empty-state-copy">换一个地区或稍后重试。</div></div>';
        return;
      }
      list.innerHTML = proxies.map(function(p, idx) {
        const selected = socks5PoolState.selected && socks5PoolState.selected.address === p.address && socks5PoolState.selected.port === p.port;
        const latency = Number(p.latency);
        const line = formatSocks5ProxyLine(p);
        const color = latency >= 0 && latency < 300 ? 'var(--green)' : (latency >= 0 && latency < 800 ? 'var(--accent2)' : 'var(--muted)');
        const optionClass = selected ? 'socks5-pool-option selected' : 'socks5-pool-option';
        return '<button type="button" onclick="selectSocks5PoolProxy(' + idx + ')" class="' + optionClass + '" style="width:100%;text-align:left;display:flex;gap:10px;align-items:center;padding:10px 12px;border:1px solid ' + (selected ? 'var(--accent)' : 'transparent') + ';border-radius:var(--radius-md);margin-bottom:6px;cursor:pointer;background:' + (selected ? 'color-mix(in srgb, var(--accent) 14%, transparent)' : 'transparent') + ';color:var(--fg);box-shadow:' + (selected ? '0 0 0 1px color-mix(in srgb, var(--accent) 55%, transparent)' : 'none') + '">' +
          '<span style="color:' + color + ';font-size:14px">' + (latency >= 0 ? '✅' : '⏳') + '</span>' +
          '<span style="flex:1;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:var(--text-xs);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + escapeHtml(line.replace(/^✅ |^⏳ /, '')) + '</span>' +
        '</button>';
      }).join('');
    }

    function selectSocks5PoolProxy(index) {
      socks5PoolState.selected = socks5PoolState.proxies[index] || null;
      renderSocks5PoolList();
      renderSocks5PoolMap();
    }

    function renderSocks5PoolMap() {
      const map = document.getElementById('socks5-pool-map');
      if (!map) return;
      const proxies = socks5PoolState.proxies || [];
      const points = proxies.map(function(p, idx) {
        const lon = Number(p.longitude || 0), lat = Number(p.latitude || 0);
        const x = lon ? Math.max(4, Math.min(96, (lon + 180) / 360 * 100)) : 50;
        const y = lat ? Math.max(6, Math.min(94, (90 - lat) / 180 * 100)) : 50;
        const selected = socks5PoolState.selected && socks5PoolState.selected.address === p.address && socks5PoolState.selected.port === p.port;
        return '<button onclick="selectSocks5PoolProxy(' + idx + ')" title="' + escapeHtml(p.city || p.address) + '" style="position:absolute;left:' + x + '%;top:' + y + '%;transform:translate(-50%,-50%);width:' + (selected ? 18 : 12) + 'px;height:' + (selected ? 18 : 12) + 'px;border-radius:50%;border:2px solid var(--surface);background:' + (selected ? 'var(--accent2)' : 'var(--accent)') + ';box-shadow:0 0 0 ' + (selected ? 8 : 4) + 'px color-mix(in srgb, var(--accent) 18%, transparent);cursor:pointer"></button>';
      }).join('');
      const selected = socks5PoolState.selected;
      map.innerHTML = '<div style="position:absolute;inset:0;opacity:.28;background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);background-size:40px 40px"></div>' +
        '<div style="position:absolute;left:18%;top:24%;width:45%;height:58%;border:1px solid color-mix(in srgb, var(--accent) 35%, transparent);border-radius:52% 38% 45% 45%;transform:rotate(-12deg);background:color-mix(in srgb, var(--accent) 8%, transparent)"></div>' +
        '<div style="position:absolute;right:12%;top:22%;width:30%;height:46%;border:1px solid color-mix(in srgb, var(--green) 25%, transparent);border-radius:48%;background:color-mix(in srgb, var(--green) 6%, transparent)"></div>' +
        points +
        (selected ? '<div style="position:absolute;left:18px;bottom:18px;right:18px;padding:12px;border:1px solid var(--line);border-radius:var(--radius-md);background:color-mix(in srgb, var(--surface) 86%, transparent);backdrop-filter:blur(6px)"><strong style="color:var(--accent2)">' + escapeHtml(selected.city || selected.country_code || selected.address) + '</strong><div class="muted" style="font-size:var(--text-xs);margin-top:4px">' + escapeHtml(selected.address + ':' + selected.port + ' · ' + (selected.asn || '') + ' · ' + (selected.organization || '')) + '</div></div>' : '');
    }

    async function confirmSocks5PoolProxy() {
      const p = socks5PoolState.selected;
      if (!p) { showToast('请选择一个 SOCKS5', 'error'); return; }
      try {
        const resp = await fetch(apiPath('/api/outbounds/socks5-pool/import'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({address:p.address, port:p.port, username:p.username, password:p.password, city:p.city, asn:p.asn, organization:p.organization})
        });
        if (!resp.ok) throw new Error('导入失败');
        showToast('SOCKS5 已添加到出站', 'success');
        closeModal();
        await loadOutbounds();
      } catch(e) { showToast('导入失败: ' + e.message, 'error'); }
    }

    function openCreateOutbound() {
      ['co-tag','co-remark','co-address'].forEach(id => document.getElementById(id).value = '');
      document.getElementById('co-protocol').value = 'socks';
      document.getElementById('co-port').value = '1080';
      document.getElementById('co-username').value = '';
      document.getElementById('co-password').value = '';
      document.getElementById('co-address-row').style.display = '';
      document.getElementById('co-port-row').style.display = '';
      document.getElementById('co-cred-row').style.display = '';
      showModal('create-outbound-dialog');
    }

    document.addEventListener('change', function(e) {
      if (e.target.id === 'co-protocol') {
        const isRemote = e.target.value === 'socks' || e.target.value === 'http';
        ['address','port','cred'].forEach(pt => {
          const el = document.getElementById('co-' + pt + '-row');
          if (el) el.style.display = isRemote ? '' : 'none';
        });
      }
      if (e.target.id === 'eo-protocol') {
        const isRemote = e.target.value === 'socks' || e.target.value === 'http';
        ['address','port','cred'].forEach(pt => {
          const el = document.getElementById('eo-' + pt + '-row');
          if (el) el.style.display = isRemote ? '' : 'none';
        });
      }
    });

    async function submitCreateOutbound() {
      const tag = document.getElementById('co-tag').value.trim();
      if (!tag) { showToast('请输入出站标识', 'error'); return; }
      const remark = document.getElementById('co-remark').value.trim() || tag;
      const protocol = document.getElementById('co-protocol').value;
      const body = {tag: tag, remark: remark, protocol: protocol};
      if (protocol === 'socks' || protocol === 'http') {
        body.address = document.getElementById('co-address').value.trim();
        if (!body.address) { showToast('请输入代理地址', 'error'); return; }
        body.port = parseInt(document.getElementById('co-port').value) || 0;
        if (body.port <= 0 || body.port > 65535) { showToast('请输入有效端口(1-65535)', 'error'); return; }
        const user = document.getElementById('co-username').value.trim();
        if (user) { body.username = user; body.password = document.getElementById('co-password').value; }
      }
      try {
        const resp = await fetch(apiPath('/api/outbounds'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) { showToast('创建失败', 'error'); return; }
        showToast('出站已创建', 'success');
        closeModal();
        await loadOutbounds();
      } catch(e) { showToast('创建失败: ' + e.message, 'error'); }
    }

    function openEditOutbound(id) {
      fetch(apiPath('/api/outbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var obs = Array.isArray(data) ? data : (data.outbounds || []);
        var ob = obs.find(function(o) { return o.id === id; });
        if (!ob) { showToast('未找到出站', 'error'); return; }
        document.getElementById('eo-id').value = ob.id;
        document.getElementById('eo-tag').value = ob.tag;
        document.getElementById('eo-remark').value = ob.remark;
        document.getElementById('eo-protocol').value = ob.protocol;
        document.getElementById('eo-address').value = ob.address || '';
        document.getElementById('eo-port').value = ob.port || '';
        document.getElementById('eo-username').value = ob.username || '';
        document.getElementById('eo-password').value = ob.password || '';
        document.getElementById('eo-enabled').checked = ob.enabled !== false;
        var isRemote = ob.protocol === 'socks' || ob.protocol === 'http';
        ['address','port','cred'].forEach(function(pt) {
          document.getElementById('eo-' + pt + '-row').style.display = isRemote ? '' : 'none';
        });
        showModal('edit-outbound-dialog');
      }).catch(function() { showToast('加载失败','error'); });
    }

    async function submitEditOutbound() {
      var id = parseInt(document.getElementById('eo-id').value);
      var tag = document.getElementById('eo-tag').value.trim();
      if (!tag) { showToast('请输入出站标识', 'error'); return; }
      var body = {
        tag: tag, remark: document.getElementById('eo-remark').value.trim() || tag,
        protocol: document.getElementById('eo-protocol').value,
        enabled: document.getElementById('eo-enabled').checked,
      };
      if (body.protocol === 'socks' || body.protocol === 'http') {
        body.address = document.getElementById('eo-address').value.trim();
        body.port = parseInt(document.getElementById('eo-port').value) || 0;
        var user = document.getElementById('eo-username').value.trim();
        if (user) { body.username = user; body.password = document.getElementById('eo-password').value; }
      }
      try {
        var resp = await fetch(apiPath('/api/outbounds/' + id), {
          method: 'PUT', headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) { showToast('更新失败', 'error'); return; }
        showToast('出站已更新', 'success');
        closeModal();
        await loadOutbounds();
      } catch(e) { showToast('更新失败: ' + e.message, 'error'); }
    }

    function deleteOutbound(id) {
      showConfirm('确认删除此出站？').then(async function(confirmed) {
        if (!confirmed) return;
        try {
          const resp = await fetch(apiPath('/api/outbounds/' + id), {method:'DELETE'});
          if (!resp.ok) { const err = await resp.json(); throw new Error(err.error || '删除失败'); }
          showToast('出站已删除', 'success');
          await loadOutbounds();
        } catch(e) { showToast('删除失败: ' + e.message, 'error'); }
      });
    }

    async function loadRoutingRules() {
      const el = document.getElementById('routing-rule-list');
      if (!el) return;
      try {
        const resp = await fetch(apiPath('/api/routing-rules'));
        if (!resp.ok) { el.innerHTML = '<div class=\"muted\" style=\"padding:12px\">加载失败</div>'; return; }
        const rules = await resp.json();
        if (!rules || !rules.length) {
          el.innerHTML = '<div class=\"empty-state\"><div class=\"empty-state-title\">暂无路由规则</div><div class=\"empty-state-copy\">添加规则可将特定域名、入站或协议的流量转发到指定出站。点击上方"新建规则"开始。</div></div>';
          return;
        }
        el.innerHTML = '<div id=\"routing-rule-drag-container\" style=\"display:grid;grid-template-columns:1fr;gap:8px\">' +
          rules.map(function(r) { return renderRoutingRuleCard(r); }).join('') +
          '</div>';
        setTimeout(attachRoutingRuleDragHandlers, 0);
      } catch(e) {
        el.innerHTML = '<div class=\"muted\" style=\"padding:12px\">加载失败</div>';
      }
    }

    function renderRoutingRuleCard(r) {
      var parts = [];
      if (r.inbound_tag) parts.push('入站: ' + escHtml(r.inbound_tag));
      if (r.domain) parts.push('域名: ' + escHtml(r.domain));
      if (r.protocol) parts.push('协议: ' + escHtml(r.protocol));
      if (!parts.length) parts.push('所有流量');
      var detail = parts.join(' & ');
      var enabledColor = r.enabled ? 'var(--green)' : 'var(--muted)';
      return '<div class=\"card\" style=\"padding:12px 16px;display:flex;align-items:center;gap:12px\" draggable=\"true\" data-rule-id=\"' + r.id + '\">' +
        '<span style=\"color:' + enabledColor + ';font-size:18px\">' + (r.enabled ? '&#9679;' : '&#9678;') + '</span>' +
        '<div style=\"flex:1;min-width:0\">' +
        '<div style=\"font-weight:600;font-size:var(--text-sm)\">' + detail + '</div>' +
        '<div class=\"muted\" style=\"font-size:var(--text-xs)\">→ ' + escHtml(r.outbound_tag) + '</div>' +
        '</div>' +
        '<button class=\"icon-btn\" onclick=\"openEditRoutingRule(this,' + r.id + ')\" title=\"编辑\" data-rule-outbound=\"' + escapeHtml(r.outbound_tag) + '\" data-rule-domain=\"' + escapeHtml(r.domain || '') + '\" data-rule-inbound=\"' + escapeHtml(r.inbound_tag || '') + '\" data-rule-protocol=\"' + escapeHtml(r.protocol || '') + '\" data-rule-enabled=\"' + (r.enabled||false) + '\">&#9998;</button>' +
        '<button class=\"danger-icon-btn\" onclick=\"deleteRoutingRule(' + r.id + ')\" title=\"删除\">&#10005;</button>' +
        '</div>';
    }


    function attachRoutingRuleDragHandlers() {
      var container = document.getElementById('routing-rule-drag-container');
      if (!container) return;
      var draggedEl = null;
      container.addEventListener('dragstart', function(e) {
        var card = e.target.closest('[draggable]');
        if (!card) return;
        draggedEl = card;
        e.dataTransfer.effectAllowed = 'move';
        card.style.opacity = '0.4';
      });
      container.addEventListener('dragend', function(e) {
        var card = e.target.closest('[draggable]');
        if (card) card.style.opacity = '';
      });
      container.addEventListener('dragover', function(e) {
        var card = e.target.closest('[draggable]');
        if (!card || card === draggedEl || !draggedEl) return;
        e.preventDefault();
        var rect = card.getBoundingClientRect();
        var mid = rect.top + rect.height / 2;
        if (e.clientY < mid) {
          container.insertBefore(draggedEl, card);
        } else {
          container.insertBefore(draggedEl, card.nextSibling);
        }
      });
      container.addEventListener('drop', function(e) {
        e.preventDefault();
        if (!draggedEl) return;
        var ids = [];
        container.querySelectorAll('[data-rule-id]').forEach(function(el) {
          ids.push(parseInt(el.getAttribute('data-rule-id')));
        });
        if (!ids.length) return;
        fetch(apiPath('/api/routing-rules/reorder'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ids: ids})
        }).then(async function(resp) {
          if (!resp.ok) { showToast('排序保存失败', 'error'); await loadRoutingRules(); return; }
          showToast('排序已保存', 'success');
        }).catch(function() { showToast('排序保存失败', 'error'); loadRoutingRules(); });
      });
    }
function openCreateRoutingRule() {
      document.getElementById('crr-domain').value = '';
      document.getElementById('crr-inbound').innerHTML = '<option value="">留空 = 所有入站</option>';
      document.getElementById('crr-protocol').value = '';
      document.getElementById('crr-enabled').checked = true;
      var sel = document.getElementById('crr-outbound');
      sel.innerHTML = '<option value="">-- 选择出站 --</option>';
      // Load outbounds for the dropdown
      fetch(apiPath('/api/outbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var obs = Array.isArray(data) ? data : (data.outbounds || []);
        obs.forEach(function(ob) {
          var opt = document.createElement('option');
          opt.value = ob.tag;
          opt.textContent = (ob.remark || ob.tag) + ' (' + ob.protocol + ')';
          sel.appendChild(opt);
        });
        sel.value = '';
      }).catch(function(e) { showToast('加载下拉选项失败: ' + e.message, 'error'); });
      // Load inbounds for the inbound dropdown
      fetch(apiPath('/api/inbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var ibs = Array.isArray(data) ? data : (data.inbounds || []);
        var ibSel = document.getElementById('crr-inbound');
        ibs.forEach(function(ib) {
          var opt = document.createElement('option');
          opt.value = ib.remark || '';
          opt.textContent = (ib.remark || '未命名') + ' (端口 ' + ib.port + ')';
          ibSel.appendChild(opt);
        });
      }).catch(function(e) { showToast('加载下拉选项失败: ' + e.message, 'error'); });
      showModal('create-routing-rule-dialog');
    }

    async function submitCreateRoutingRule() {
      var outboundTag = document.getElementById('crr-outbound').value;
      if (!outboundTag) { showToast('请选择目标出站', 'error'); return; }
      var body = {
        outbound_tag: outboundTag,
        domain: document.getElementById('crr-domain').value.trim(),
        inbound_tag: document.getElementById('crr-inbound').value.trim(),
        protocol: document.getElementById('crr-protocol').value.trim(),
        enabled: document.getElementById('crr-enabled').checked,
      };
      try {
        var resp = await fetch(apiPath('/api/routing-rules'), {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) { showToast('创建失败', 'error'); return; }
        showToast('路由规则已创建', 'success');
        closeModal();
        await refreshRoutingRuleViews();
      } catch(e) { showToast('创建失败: ' + e.message, 'error'); }
    }

    async function refreshRoutingRuleViews() {
      const tasks = [loadRoutingRules()];
      if (typeof loadXrayStatus === 'function') tasks.push(loadXrayStatus());
      await Promise.allSettled(tasks);
    }

    function deleteRoutingRule(id) {
      showConfirm('确认删除此路由规则？').then(async function(confirmed) {
        if (!confirmed) return;
        try {
          var resp = await fetch(apiPath('/api/routing-rules/' + id), {method:'DELETE'});
          if (!resp.ok) { showToast('删除失败', 'error'); return; }
          showToast('路由规则已删除', 'success');
          await refreshRoutingRuleViews();
        } catch(e) { showToast('删除失败: ' + e.message, 'error'); }
      });
    }

    function openEditRoutingRule(btn, id) {
      var outboundTag = btn.getAttribute('data-rule-outbound');
      var domain = btn.getAttribute('data-rule-domain');
      var inboundTag = btn.getAttribute('data-rule-inbound');
      var protocol = btn.getAttribute('data-rule-protocol');
      var enabled = btn.getAttribute('data-rule-enabled') !== 'false';
      document.getElementById('err-id').value = id;
      document.getElementById('err-domain').value = domain || '';
      document.getElementById('err-inbound').innerHTML = '<option value="">留空 = 所有入站</option>';
      document.getElementById('err-protocol').value = protocol || '';
      document.getElementById('err-enabled').checked = enabled !== false;
      var sel = document.getElementById('err-outbound');
      sel.innerHTML = '<option value="">-- 选择出站 --</option>';
      fetch(apiPath('/api/outbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var obs = Array.isArray(data) ? data : (data.outbounds || []);
        obs.forEach(function(ob) {
          var opt = document.createElement('option');
          opt.value = ob.tag;
          opt.textContent = (ob.remark || ob.tag) + ' (' + ob.protocol + ')';
          sel.appendChild(opt);
          if (ob.tag === outboundTag) opt.selected = true;
        });
      }).catch(function(e) { showToast('加载下拉选项失败: ' + e.message, 'error'); });
      // Load inbounds for the inbound dropdown
      fetch(apiPath('/api/inbounds')).then(function(r) { return r.json(); }).then(function(data) {
        var ibs = Array.isArray(data) ? data : (data.inbounds || []);
        var ibSel = document.getElementById('err-inbound');
        ibs.forEach(function(ib) {
          var opt = document.createElement('option');
          opt.value = ib.remark || '';
          opt.textContent = (ib.remark || '未命名') + ' (端口 ' + ib.port + ')';
          ibSel.appendChild(opt);
          if ((ib.remark || '') === (inboundTag || '')) opt.selected = true;
        });
      }).catch(function(e) { showToast('加载下拉选项失败: ' + e.message, 'error'); });
      showModal('edit-routing-rule-dialog');
    }

    async function submitEditRoutingRule() {
      var id = parseInt(document.getElementById('err-id').value);
      var outboundTag = document.getElementById('err-outbound').value;
      if (!outboundTag) { showToast('请选择目标出站', 'error'); return; }
      var body = {
        outbound_tag: outboundTag,
        domain: document.getElementById('err-domain').value.trim(),
        inbound_tag: document.getElementById('err-inbound').value.trim(),
        protocol: document.getElementById('err-protocol').value.trim(),
        enabled: document.getElementById('err-enabled').checked,
      };
      try {
        var resp = await fetch(apiPath('/api/routing-rules/' + id), {
          method: 'PUT', headers: {'Content-Type':'application/json'},
          body: JSON.stringify(body)
        });
        if (!resp.ok) { showToast('保存失败', 'error'); return; }
        showToast('路由规则已更新', 'success');
        closeModal();
        await refreshRoutingRuleViews();
      } catch(e) { showToast('保存失败: ' + e.message, 'error'); }
    }

    function preferredTheme() {
      const saved = localStorage.getItem('migate-theme');
      if (saved === 'dark' || saved === 'light') return saved;
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function applyTheme(theme) {
      if (theme !== 'dark') theme = 'light';
      document.documentElement.dataset.theme = theme;
      localStorage.setItem('migate-theme', theme);
      const btn = document.getElementById('theme-toggle');
      if (btn) btn.textContent = theme === 'dark' ? '浅色模式' : '深色模式';
    }

    function toggleTheme() {
      applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    }

    async function loadSession() {
      try {
        const res = await fetch(apiPath('/api/session'));
        const session = await res.json();
        const name = document.getElementById('current-username');
        const loginBtn = document.getElementById('login-button');
        const logoutBtn = document.getElementById('logout-button');
        const authenticated = !!session.authenticated;
        if (name) name.textContent = session.username || (session.auth_enabled ? '未登录' : '未启用认证');
        if (loginBtn) loginBtn.style.display = authenticated ? 'none' : '';
        if (logoutBtn) logoutBtn.style.display = authenticated ? '' : 'none';
      } catch (e) {
        const name = document.getElementById('current-username');
        if (name) name.textContent = '无法读取用户';
      }
    }

    async function logoutPanel() {
      const res = await fetch(apiPath('/api/logout'), {method: 'POST'});
      if (!res.ok) { showToast('登出失败', 'error'); return; }
      showToast('已登出', 'success');
      window.location.href = panelPath('/login');
    }

    function toggleSidebar() {
      document.querySelector('.app-shell').classList.toggle('sidebar-open');
    }
    function closeSidebar() {
      document.querySelector('.app-shell').classList.remove('sidebar-open');
    }
    function toggleClientSection(inboundId) {
      const el = document.getElementById('client-section-' + inboundId);
      if (!el) return;
      if (el.style.display !== 'none') {
        el.style.display = 'none';
        return;
      }
      el.style.display = 'block';
      el.innerHTML = '<div class="list" style="margin:0">正在加载客户端...</div>';
      fetch(apiPath('/api/inbounds')).then(r => r.json()).then(data => {
        const inbound = (data.inbounds || []).find(i => i.id === inboundId);
        if (!inbound) { el.innerHTML = '<div class="muted" style="padding:12px">入站未找到</div>'; return; }
        renderClients(inbound, el.querySelector('.list') || el);
        // Append "新增客户端" button at bottom
        const btnWrap = document.createElement('div');
        btnWrap.className = 'client-add-row';
        btnWrap.innerHTML = '<button onclick="openCreateClient(' + inboundId + ')" class="btn-sm">新增客户端</button>';
        el.appendChild(btnWrap);
      }).catch(() => {
        el.innerHTML = '<div class="muted" style="padding:12px">加载失败</div>';
      });
    }

    async function loadStats() {
      try {
        const resp = await fetch(apiPath('/api/stats'));
        if (!resp.ok) return;
        const s = await resp.json();
        document.getElementById('inbound-count').textContent = s.inbounds;
        document.getElementById('client-count').textContent = s.clients;
        document.getElementById('outbound-stats').textContent = s.outbounds_enabled + ' / ' + s.outbounds;
        document.getElementById('routing-stats').textContent = s.routing_rules_enabled + ' / ' + s.routing_rules;
      } catch(e) {}
    }

    applyTheme(preferredTheme());
    loadSession();

    loadInbounds();
    loadOutbounds();
    loadRoutingRules();
    loadStats();

    // === Navigation section switching ===
    function currentSectionFromLocation() {
      const hash = window.location.hash.replace('#', '');
      return hash || 'overview';
    }

    function navigateTo(sectionId) {
      const validSections = ['overview', 'inbounds', 'clients', 'outbound', 'routing', 'xray', 'singbox', 'settings'];
      if (!validSections.includes(sectionId)) sectionId = 'overview';
      document.querySelectorAll('main > section').forEach((el) => {
        const display = el.classList.contains('overview-grid') ? 'grid' : 'block';
        el.style.display = (el.id === sectionId) ? display : 'none';
      });
      document.querySelectorAll('nav a').forEach((a) => {
        const href = a.getAttribute('href');
        a.classList.toggle('active', (sectionId === 'overview' && href === '#') || href === '#' + sectionId);
      });
      history.replaceState(null, '', sectionId === 'overview' ? panelPath('/') : panelPath('/#' + sectionId));
      if (sectionId === 'overview') { loadStats(); loadOverviewServiceStatuses(); }
      if (sectionId === 'xray') fetchXrayStatus();
      if (sectionId === 'singbox') fetchSingboxStatus();
    }
    document.querySelectorAll('nav a').forEach((a) => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        closeSidebar();
        const href = a.getAttribute('href');
        if (href === '#') { navigateTo('overview'); return; }
        const id = href.replace('#', '');
        navigateTo(id);
      });
    });
    window.addEventListener('hashchange', () => navigateTo(currentSectionFromLocation()));
    navigateTo(currentSectionFromLocation());

    function renderClients(inbound, list) {
      const hostName = window.location.hostname;
      const clients = inbound.clients || [];
      if (clients.length === 0) {
        list.className = 'list';
        list.innerHTML = renderEmptyState('暂无客户端', '在当前入站下创建第一个客户端后，即可复制订阅或分享链接。', [
          {label:'创建客户端', onclick:"openCreateClient(" + inbound.id + ")"}
        ]);
        return;
      }
      list.className = 'list';
      list.innerHTML = clients.map(c => {
        let shareLink;
        if (inbound.protocol === 'vmess') {
          var vmessHost = '', vmessPath = '', vmessSni = '';
          if (inbound.network === 'ws' || inbound.network === 'h2') {
            vmessHost = inbound.ws_host || '';
            vmessPath = inbound.ws_path || '';
          } else if (inbound.network === 'grpc') {
            vmessPath = inbound.grpc_service_name || '';
          } else if (inbound.network === 'xhttp') {
            vmessPath = inbound.xhttp_path || '';
          }
          if (inbound.security === 'tls' || inbound.security === 'reality') {
            vmessSni = inbound.reality_server_names || '';
          }
          var vmessData = {v:'2',ps:c.email,add:hostName,port:String(inbound.port),id:c.uuid,aid:'0',scy:'auto',net:inbound.network||'tcp',type:'none',host:vmessHost,path:vmessPath,tls:(inbound.security==='tls'||inbound.security==='reality')?'tls':'',sni:vmessSni};
          try { shareLink = 'vmess://' + btoa(JSON.stringify(vmessData)); } catch(e) { shareLink = ''; }
        } else if (inbound.protocol === 'shadowsocks') {
          var ssMethod = inbound.ss_method || '2022-blake3-aes-128-gcm';
          var userPass = ssMethod + ':' + inbound.uuid;
          try { shareLink = 'ss://' + btoa(userPass) + '@' + hostName + ':' + inbound.port + '#' + escapeHtml(c.email); } catch(e) { shareLink = ''; }
        } else {
          var p = [];
          p.push('type=' + (inbound.network||'tcp'));
          p.push('security=' + (inbound.security||'none'));
          if (inbound.security === 'reality') {
            if (inbound.network !== 'xhttp') p.push('flow=xtls-rprx-vision');
            if (inbound.reality_server_names) p.push('sni=' + encodeURIComponent(inbound.reality_server_names));
            p.push('fp=chrome');
            if (inbound.reality_public_key) p.push('pbk=' + encodeURIComponent(inbound.reality_public_key));
            if (inbound.reality_short_id) p.push('sid=' + encodeURIComponent(inbound.reality_short_id));
          } else if (inbound.security === 'tls') {
            if (inbound.reality_server_names) p.push('sni=' + encodeURIComponent(inbound.reality_server_names));
            p.push('allowInsecure=1');
          }
          if (inbound.network === 'ws') {
            if (inbound.ws_path) p.push('path=' + encodeURIComponent(inbound.ws_path));
            if (inbound.ws_host) p.push('host=' + encodeURIComponent(inbound.ws_host));
          } else if (inbound.network === 'h2') {
            if (inbound.ws_path) p.push('path=' + encodeURIComponent(inbound.ws_path));
            if (inbound.ws_host) p.push('host=' + encodeURIComponent(inbound.ws_host));
          } else if (inbound.network === 'grpc') {
            if (inbound.grpc_service_name) p.push('serviceName=' + encodeURIComponent(inbound.grpc_service_name));
          } else if (inbound.network === 'xhttp') {
            if (inbound.xhttp_path) p.push('path=' + encodeURIComponent(inbound.xhttp_path));
            if (inbound.xhttp_mode) p.push('mode=' + encodeURIComponent(inbound.xhttp_mode));
          }
          shareLink = inbound.protocol + '://' + c.uuid + '@' + hostName + ':' + inbound.port + '?' + p.join('&') + '#' + escapeHtml(c.email);
        }
        const used = (c.up||0) + (c.down||0);
        const limit = c.traffic_limit || 0;
        const pct = limit > 0 ? Math.min(100, used / limit * 100) : 0;
        const isOverLimit = limit > 0 && used >= limit;
        const isExpired = c.expiry_at && c.expiry_at > 0 && c.expiry_at <= Math.floor(Date.now() / 1000);
        const expiredText = c.expiry_at && c.expiry_at > 0 ? new Date(c.expiry_at * 1000).toLocaleDateString() : '不限';
        const expireStyle = isExpired ? 'color:var(--danger);font-weight:500' : '';
        const trafficStyle = isOverLimit ? 'color:var(--danger)' : '';
        const badgeClass = c.enabled && !isExpired && !isOverLimit ? 'enabled' : 'disabled';
        const badgeText = c.enabled ? (isExpired ? 'Expired' : (isOverLimit ? 'Limited' : 'Enabled')) : 'Disabled';
        const fillClass = isOverLimit ? 'bar-high' : (pct >= 85 ? 'bar-mid' : 'bar-low');
        return '<div class="client-resource-row">' +
          '<div class="resource-main">' +
            '<div class="resource-title"><strong>' + escapeHtml(c.email) + '</strong><span class="status-badge ' + badgeClass + '">' + badgeText + '</span></div>' +
            '<div class="resource-meta">' +
              '<span class="mono">' + c.uuid.substring(0,8) + '…</span>' +
              '<span style="' + trafficStyle + '">↑' + formatBytes(c.up||0) + ' ↓' + formatBytes(c.down||0) + '</span>' +
              '<span>' + formatBytes(used) + ' / ' + (limit > 0 ? formatBytes(limit) : '∞') + '</span>' +
              '<span style="' + expireStyle + '">到期 ' + expiredText + '</span>' +
              (limit > 0 ? '<span><div class="traffic-track"><div class="traffic-fill ' + fillClass + '" style="width:' + pct + '%"></div></div></span>' : '') +
            '</div>' +
          '</div>' +
          '<div class="resource-actions">' +
            '<button class="icon-btn" onclick="copySubUrl(' + htmlAttrString(shareLink) + ')" title="复制分享链接">Link</button>' +
            '<button class="icon-btn" onclick="editClient(' + c.id + ',' + inbound.id + ')" title="编辑">Edit</button>' +
            '<button class="icon-btn" onclick="toggleClient(' + c.id + ')" title="启用/禁用">' + (c.enabled ? 'ON' : 'OFF') + '</button>' +
            '<button class="danger-icon-btn" onclick="deleteClient(' + inbound.id + ',' + c.id + ')" title="删除">DEL</button>' +
          '</div>' +
        '</div>';
      }).join('');
    }

    function formatBytes(bytes) {
      if (!bytes || bytes === 0) return '0 B';
      const units = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(1024));
      return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    }

    function jsString(value) {
      return JSON.stringify(String(value || ''));
    }

    function htmlAttrString(value) {
      return jsString(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function copyTextFallback(text) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try {
        return document.execCommand('copy');
      } finally {
        document.body.removeChild(ta);
      }
    }

    async function copySubUrl(text) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        } else if (!copyTextFallback(text)) {
          throw new Error('copy fallback failed');
        }
        showToast('已复制链接', 'success');
      } catch (e) {
        try {
          if (copyTextFallback(text)) {
            showToast('已复制链接', 'success');
            return;
          }
        } catch (_) {}
        showToast('复制失败，请手动复制', 'error');
      }
    }

    async function deleteInbound(id) {
      if (!await showConfirm('确认删除入站 ' + id + '？此操作不可撤销，其下的客户端也将被删除。')) return;
      const response = await fetch(apiPath('/api/inbounds/') + id, {method: 'DELETE'});
      if (!response.ok) {
        showToast('删除失败：' + await response.text(), 'error');
        return;
      }
      await loadInbounds();
    }

    async function deleteClient(inboundId, clientId) {
      if (!await showConfirm('确认删除客户端 ' + clientId + '？')) return;
      const response = await fetch(apiPath('/api/inbounds/') + inboundId + '/clients/' + clientId, {method: 'DELETE'});
      if (!response.ok) {
        showToast('删除失败：' + await response.text(), 'error');
        return;
      }
      await loadInbounds();
    }

    // === Edit & toggle functions ===
    let _editingInboundId = null;
    let _editingClientData = null;

    function eiUpdateDynamicFields() {
      const proto = document.getElementById('ei-protocol').value;
      const net = document.getElementById('ei-network').value;
      const sec = document.getElementById('ei-security').value;
      document.getElementById('ei-ws-settings').classList.toggle('hidden', net !== 'ws' && net !== 'h2');
      document.getElementById('ei-grpc-settings').classList.toggle('hidden', net !== 'grpc');
      document.getElementById('ei-xhttp-settings').classList.toggle('hidden', net !== 'xhttp');
      document.getElementById('ei-reality-settings').classList.toggle('hidden', sec !== 'reality');
      document.getElementById('ei-ss-settings').classList.toggle('hidden', proto !== 'shadowsocks');
      document.getElementById('ei-tls-settings').classList.toggle('hidden', sec !== 'tls');
      document.getElementById('ei-hy2-settings').classList.toggle('hidden', proto !== 'hysteria2');
      document.getElementById('ei-tuic-settings').classList.toggle('hidden', proto !== 'tuic');
      document.getElementById('ei-wireguard-settings').classList.toggle('hidden', proto !== 'wireguard');
      document.getElementById('ei-shadowtls-settings').classList.toggle('hidden', proto !== 'shadowtls');
    }

    async function editInbound(id) {
      const res = await fetch(apiPath('/api/inbounds'));
      const data = await res.json();
      const inbound = (data.inbounds || []).find(i => i.id === id);
      if (!inbound) { showToast('入站未找到', 'error'); return; }
      _editingInboundId = id;
      document.getElementById('ei-remark').value = inbound.remark || '';
      document.getElementById('ei-protocol').value = inbound.protocol || 'vless';
      document.getElementById('ei-port').value = inbound.port || '';
      document.getElementById('ei-network').value = inbound.network || 'tcp';
      document.getElementById('ei-security').value = inbound.security || 'none';
      document.getElementById('ei-ws-path').value = inbound.ws_path || '';
      document.getElementById('ei-ws-host').value = inbound.ws_host || '';
      document.getElementById('ei-grpc-service-name').value = inbound.grpc_service_name || 'migate';
      document.getElementById('ei-xhttp-path').value = inbound.xhttp_path || '/';
      document.getElementById('ei-xhttp-mode').value = inbound.xhttp_mode || 'stream-one';
      document.getElementById('ei-reality-dest').value = inbound.reality_dest || '';
      document.getElementById('ei-reality-server-names').value = inbound.reality_server_names || '';
      document.getElementById('ei-reality-short-id').value = inbound.reality_short_id || '';
      document.getElementById('ei-reality-private-key').value = inbound.reality_private_key || '';
      document.getElementById('ei-ss-method').value = inbound.ss_method || '2022-blake3-aes-128-gcm';
      document.getElementById('ei-tls-cert-file').value = inbound.tls_cert_file || '';
      document.getElementById('ei-tls-key-file').value = inbound.tls_key_file || '';
      document.getElementById('ei-tls-sni').value = inbound.tls_sni || '';
      document.getElementById('ei-tls-fingerprint').value = inbound.tls_fingerprint || '';
      document.getElementById('ei-tls-alpn').value = inbound.tls_alpn || '';
      document.getElementById('ei-hy2-up').value = inbound.hy2_up_mbps || 0;
      document.getElementById('ei-hy2-down').value = inbound.hy2_down_mbps || 0;
      document.getElementById('ei-hy2-obfs').value = inbound.hy2_obfs || '';
      document.getElementById('ei-hy2-obfs-password').value = inbound.hy2_obfs_password || '';
      document.getElementById('ei-tuic-cc').value = inbound.tuic_congestion_control || 'bbr';
      document.getElementById('ei-tuic-zero-rtt').checked = inbound.tuic_zero_rtt || false;
      document.getElementById('ei-wg-private-key').value = inbound.wg_private_key || '';
      document.getElementById('ei-wg-address').value = inbound.wg_address || '';
      document.getElementById('ei-wg-peer-public-key').value = inbound.wg_peer_public_key || '';
      document.getElementById('ei-wg-allowed-ips').value = inbound.wg_allowed_ips || '';
      document.getElementById('ei-wg-endpoint').value = inbound.wg_endpoint || '';
      document.getElementById('ei-wg-preshared-key').value = inbound.wg_preshared_key || '';
      document.getElementById('ei-wg-mtu').value = inbound.wg_mtu || 1420;
      document.getElementById('ei-shadowtls-password').value = inbound.shadowtls_password || '';
      document.getElementById('ei-shadowtls-version').value = inbound.shadowtls_version || 3;
      eiUpdateDynamicFields();
      document.getElementById('edit-inbound-overlay').classList.remove('hidden');
    }
    function closeEditInbound() {
      _editingInboundId = null;
      document.getElementById('edit-inbound-overlay').classList.add('hidden');
    }
    async function saveEditInbound() {
      const id = _editingInboundId;
      if (id === null) return;
      const data = {
        remark: document.getElementById('ei-remark').value.trim() || '-',
        protocol: document.getElementById('ei-protocol').value,
        port: parseInt(document.getElementById('ei-port').value) || 0,
        network: document.getElementById('ei-network').value,
        security: document.getElementById('ei-security').value,
        ws_path: document.getElementById('ei-ws-path').value,
        ws_host: document.getElementById('ei-ws-host').value,
        grpc_service_name: document.getElementById('ei-grpc-service-name').value,
        xhttp_path: document.getElementById('ei-xhttp-path').value,
        xhttp_mode: document.getElementById('ei-xhttp-mode').value,
        reality_dest: document.getElementById('ei-reality-dest').value,
        reality_server_names: document.getElementById('ei-reality-server-names').value,
        reality_short_id: document.getElementById('ei-reality-short-id').value,
        reality_private_key: document.getElementById('ei-reality-private-key').value,
        ss_method: document.getElementById('ei-ss-method').value,
        tls_cert_file: document.getElementById('ei-tls-cert-file').value,
        tls_key_file: document.getElementById('ei-tls-key-file').value,
        tls_sni: document.getElementById('ei-tls-sni').value,
        tls_fingerprint: document.getElementById('ei-tls-fingerprint').value,
        tls_alpn: document.getElementById('ei-tls-alpn').value,
        hy2_up_mbps: Number(document.getElementById('ei-hy2-up').value) || 0,
        hy2_down_mbps: Number(document.getElementById('ei-hy2-down').value) || 0,
        hy2_obfs: document.getElementById('ei-hy2-obfs').value,
        hy2_obfs_password: document.getElementById('ei-hy2-obfs-password').value,
        tuic_congestion_control: document.getElementById('ei-tuic-cc').value,
        tuic_zero_rtt: document.getElementById('ei-tuic-zero-rtt').checked,
        wg_private_key: document.getElementById('ei-wg-private-key').value,
        wg_address: document.getElementById('ei-wg-address').value,
        wg_peer_public_key: document.getElementById('ei-wg-peer-public-key').value,
        wg_allowed_ips: document.getElementById('ei-wg-allowed-ips').value,
        wg_endpoint: document.getElementById('ei-wg-endpoint').value,
        wg_preshared_key: document.getElementById('ei-wg-preshared-key').value,
        wg_mtu: Number(document.getElementById('ei-wg-mtu').value) || 1420,
        shadowtls_password: document.getElementById('ei-shadowtls-password').value,
        shadowtls_version: Number(document.getElementById('ei-shadowtls-version').value) || 3,
      };
      if (!data.remark || !data.port) { showToast('请填写备注和端口', 'error'); return; }
      // Port conflict check (client-side, exclude current inbound)
      const existingInbounds = window._cachedInbounds || [];
      const conflictInb = existingInbounds.find(ib => ib.id !== id && ib.port === data.port);
      if (conflictInb) { showToast('端口 ' + data.port + ' 已被入站 ' + (conflictInb.remark || conflictInb.id) + ' 使用', 'error'); return; }
      const res = await fetch(apiPath('/api/inbounds/') + id, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      });
      if (!res.ok) { showToast('编辑入站失败', 'error'); return; }
      showToast('入站已更新', 'success');
      closeEditInbound();
      await loadInbounds();
    }
    document.getElementById('ei-protocol').addEventListener('change', eiUpdateDynamicFields);
    document.getElementById('ei-network').addEventListener('change', eiUpdateDynamicFields);
    document.getElementById('ei-security').addEventListener('change', eiUpdateDynamicFields);

    async function toggleInbound(id) {
      const response = await fetch(apiPath('/api/inbounds'));
      const data = await response.json();
      const inbound = (data.inbounds || []).find(i => i.id === id);
      if (!inbound) return;
      inbound.enabled = !inbound.enabled;
      const res = await fetch(apiPath('/api/inbounds/') + id + '/enabled', {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: inbound.enabled})
      });
      if (!res.ok) {
        showToast('开关入站失败', 'error');
        return;
      }
      showToast('入站 ' + (inbound.enabled ? '已启用' : '已禁用'), 'success');
      await loadInbounds();
    }

    async function editClient(id, inboundId) {
      const res = await fetch(apiPath('/api/inbounds'));
      const data = await res.json();
      const inbound = (data.inbounds || []).find(i => inboundId ? i.id === inboundId : true);
      const allClients = (inbound && inbound.clients) || [];
      // Search across all inbounds for the client
      let client = allClients.find(c => c.id === id);
      if (!client) {
        for (const ib of (data.inbounds || [])) {
          client = (ib.clients || []).find(c => c.id === id);
          if (client) break;
        }
      }
      if (!client) { showToast('客户端未找到', 'error'); return; }
      _editingClientData = {id: id, inboundId: client.inbound_id};
      document.getElementById('ec-email').value = client.email || '';
      document.getElementById('ec-enabled').checked = client.enabled;
      document.getElementById('ec-enabled-label').textContent = client.enabled ? '已启用' : '已禁用';
      document.getElementById('ec-enabled').onchange = function() {
        document.getElementById('ec-enabled-label').textContent = this.checked ? '已启用' : '已禁用';
      };
      document.getElementById('ec-traffic-limit').value = client.traffic_limit || '';
      document.getElementById('ec-up-display').textContent = formatBytes(client.up || 0);
      document.getElementById('ec-down-display').textContent = formatBytes(client.down || 0);
      document.getElementById('ec-total-display').textContent = formatBytes((client.up || 0) + (client.down || 0));
      if (client.expiry_at && client.expiry_at > 0) {
        const d = new Date(client.expiry_at * 1000);
        document.getElementById('ec-expiry-at').value = d.toISOString().slice(0,16);
      } else {
        document.getElementById('ec-expiry-at').value = '';
      }
      document.getElementById('edit-client-overlay').classList.remove('hidden');
    }
    function closeEditClient() {
      _editingClientData = null;
      document.getElementById('edit-client-overlay').classList.add('hidden');
    }
    async function saveEditClient() {
      const d = _editingClientData;
      if (!d) return;
      const email = document.getElementById('ec-email').value.trim();
      if (!email) { showToast('请输入客户端标识', 'error'); return; }
      const tl = parseInt(document.getElementById('ec-traffic-limit').value) || 0;
      const eaStr = document.getElementById('ec-expiry-at').value;
      let ea = 0;
      if (eaStr) { ea = Math.floor(new Date(eaStr).getTime() / 1000); }
      const res = await fetch(apiPath('/api/inbounds/') + d.inboundId + '/clients/' + d.id, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          email: email,
          enabled: document.getElementById('ec-enabled').checked,
          traffic_limit: tl,
          expiry_at: ea
        })
      });
      if (!res.ok) { showToast('编辑客户端失败', 'error'); return; }
      showToast('客户端已更新', 'success');
      closeEditClient();
      await loadInbounds();
    }

    async function toggleClient(id) {
      const inboundRes = await fetch(apiPath('/api/inbounds'));
      const data = await inboundRes.json();
      const inbounds = data.inbounds || [];
      let foundInbound = null, foundClient = null;
      for (const ib of inbounds) {
        const c = (ib.clients || []).find(c => c.id === id);
        if (c) { foundInbound = ib; foundClient = c; break; }
      }
      if (!foundInbound || !foundClient) return;
      foundClient.enabled = !foundClient.enabled;
      const res = await fetch(apiPath('/api/inbounds/') + foundInbound.id + '/clients/' + id + '/enabled', {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: foundClient.enabled})
      });
      if (!res.ok) {
        showToast('开关客户端失败', 'error');
        return;
      }
      showToast('客户端 ' + (foundClient.enabled ? '已启用' : '已禁用'), 'success');
      await loadInbounds();
    }

    async function resetClientTraffic() {
      const d = _editingClientData;
      if (!d) return;
      const confirmed = await showConfirm('确定要重置此客户端的流量数据吗？此操作不可恢复。');
      if (!confirmed) return;
      const res = await fetch(apiPath('/api/inbounds/') + d.inboundId + '/clients/' + d.id + '/reset-traffic', {
        method: 'POST'
      });
      if (!res.ok) {
        showToast('重置流量失败', 'error');
        return;
      }
      const updated = await res.json();
      document.getElementById('ec-up-display').textContent = formatBytes(updated.up || 0);
      document.getElementById('ec-down-display').textContent = formatBytes(updated.down || 0);
      document.getElementById('ec-total-display').textContent = formatBytes((updated.up || 0) + (updated.down || 0));
      showToast('流量已重置', 'success');
      await loadInbounds();
    }

    function openCreateClient(inboundId) {
      document.getElementById('client-inbound-id').value = inboundId || '';
      const formEl = document.getElementById('create-client-form');
      formEl.reset();
      regenerateField('client-uuid');
      document.getElementById('create-client-overlay').classList.remove('hidden');
      document.getElementById('client-email').focus();
    }
    function closeCreateClient() {
      document.getElementById('create-client-overlay').classList.add('hidden');
    }
    async function saveCreateClient() {
      const formEl = document.getElementById('create-client-form');
      const inboundId = document.getElementById('client-inbound-id').value;
      if (!inboundId) {
        showToast('请先展开入站再创建客户端', 'error');
        closeCreateClient();
        return;
      }
      const form = new FormData(formEl);
      const email = form.get('email');
      if (!email) { showToast('请输入客户端标识', 'error'); return; }
      const tl = parseInt(form.get('traffic_limit')) || 0;
      const clientUUID = String(form.get('uuid') || '').trim();
      const eaStr = document.getElementById('client-expiry').value;
      let ea = 0;
      if (eaStr) { ea = Math.floor(new Date(eaStr).getTime() / 1000); }
      const response = await fetch(apiPath('/api/inbounds/') + inboundId + '/clients', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email: email, uuid: clientUUID, traffic_limit: tl, expiry_at: ea})
      });
      if (!response.ok) {
        showToast('创建客户端失败：' + await response.text(), 'error');
        return;
      }
      formEl.reset();
      closeCreateClient();
      showToast('客户端创建成功', 'success');
      await loadInbounds();
    }

    // === Toast notification ===
    function showToast(msg, type) {
      const container = document.getElementById('toast-container');
      const el = document.createElement('div');
      el.className = 'toast' + (type === 'error' ? ' error' : type === 'success' ? ' success' : '');
      el.textContent = msg;
      container.appendChild(el);
      setTimeout(() => el.remove(), 3000);
    }

    // === Modal confirm (replaces native confirm()) ===
    let _confirmResolve = null;
    function showConfirm(msg) {
      return new Promise((resolve) => {
        _confirmResolve = resolve;
        document.getElementById('confirm-msg').textContent = msg;
        var overlay = document.getElementById('confirm-overlay');
        overlay.classList.remove('hidden');
        overlay.style.display = '';
      });
    }
    function resolveConfirm() {
      document.getElementById('confirm-overlay').classList.add('hidden');
      if (_confirmResolve) { _confirmResolve(true); _confirmResolve = null; }
    }
    function rejectConfirm() {
      document.getElementById('confirm-overlay').classList.add('hidden');
      if (_confirmResolve) { _confirmResolve(false); _confirmResolve = null; }
    }

    // === Dynamic transport/security fields ===
    const protocolPresets = {
      vless: {network: 'tcp', security: 'reality'},
      vmess: {network: 'ws', security: 'tls'},
      trojan: {network: 'tcp', security: 'tls'},
      shadowsocks: {network: 'tcp', security: 'none'},
      hysteria2: {network: 'quic', security: 'none'},
      tuic: {network: 'quic', security: 'tls'},
      wireguard: {network: 'udp', security: 'none'},
      shadowtls: {network: 'tcp', security: 'tls'},
    };
    function applyProtocolPreset(proto) {
      const preset = protocolPresets[proto];
      if (!preset) return;
      document.getElementById('inbound-network').value = preset.network;
      document.getElementById('inbound-security').value = preset.security;
      const inboundCredential = document.getElementById('inbound-uuid');
      const initCredential = document.getElementById('init-client-uuid');
      if (inboundCredential) inboundCredential.value = '';
      if (initCredential) initCredential.value = '';
      onProtocolChange();
    }
    function onProtocolChange() {
      const proto = document.getElementById('inbound-protocol').value;
      const isSingbox = ['hysteria2','tuic','wireguard','shadowtls'].includes(proto);
      const desc = document.getElementById('protocol-description');

      // Protocol descriptions
      const labels = {
        vless: 'VLESS + Reality：高性能，推荐优先使用。',
        vmess: 'VMess + WebSocket + TLS：适合 CDN 反代场景。',
        trojan: 'Trojan + TLS：兼容性广泛的协议。',
        shadowsocks: 'Shadowsocks：轻量加密代理。',
        hysteria2: 'Hysteria2：基于 QUIC 的 UDP 加速协议，抗丢包。',
        tuic: 'TUIC：基于 QUIC 的低延迟 UDP 代理，适合弱网环境。',
        wireguard: 'WireGuard ⚠️ 当前需要升级 sing-box 至 v1.14+ 才能生效。',
        shadowtls: 'ShadowTLS：将流量伪装成标准 TLS 连接，可绕过深度包检测。',
      };
      desc.textContent = labels[proto] || '';

      // For sing-box protocols: hide Xray-specific fields
      const netGroup = document.getElementById('inbound-network').closest('.field-group');
      const secGroup = document.getElementById('inbound-security').closest('.field-group');
      const uuidGroup = document.getElementById('inbound-uuid').closest('.field-group');

      if (isSingbox) {
        netGroup.style.display = 'none';
        secGroup.style.display = 'none';
        if (proto === 'wireguard') {
          uuidGroup.style.display = 'none';
        } else {
          uuidGroup.style.display = '';
        }
      } else {
        netGroup.style.display = '';
        secGroup.style.display = '';
        uuidGroup.style.display = '';
      }
    }
    function updateDynamicFields() {
      const proto = document.getElementById('inbound-protocol').value;
      const net = document.getElementById('inbound-network').value;
      const sec = document.getElementById('inbound-security').value;
      document.getElementById('ws-settings').classList.toggle('hidden', net !== 'ws' && net !== 'h2');
      document.getElementById('grpc-settings').classList.toggle('hidden', net !== 'grpc');
      document.getElementById('xhttp-settings').classList.toggle('hidden', net !== 'xhttp');
      document.getElementById('reality-settings').classList.toggle('hidden', sec !== 'reality');
      document.getElementById('ss-settings').classList.toggle('hidden', proto !== 'shadowsocks');
      document.getElementById('tls-settings').classList.toggle('hidden', sec !== 'tls');
      document.getElementById('hy2-settings').classList.toggle('hidden', proto !== 'hysteria2');
      document.getElementById('tuic-settings').classList.toggle('hidden', proto !== 'tuic');
      document.getElementById('wireguard-settings').classList.toggle('hidden', proto !== 'wireguard');
      document.getElementById('shadowtls-settings').classList.toggle('hidden', proto !== 'shadowtls');
      const formEl = document.getElementById('create-inbound-form');
      if (formEl) fillRandomDefaults(formEl);
    }

    function openCreateInbound() {
      const formEl = document.getElementById('create-inbound-form');
      formEl.reset();
      applyProtocolPreset(document.getElementById('inbound-protocol').value);
      document.getElementById('init-client-fields').classList.remove('hidden');
      document.querySelector('#create-inbound-dialog .chevron').textContent = '\u25BC';
      updateDynamicFields();
      onProtocolChange();
      fillRandomDefaults(formEl);
      document.getElementById('create-inbound-overlay').classList.remove('hidden');
      document.getElementById('inbound-remark').focus();
    }
    function closeCreateInbound() {
      document.getElementById('create-inbound-overlay').classList.add('hidden');
    }
    function toggleInitClient(el) {
      const fields = document.getElementById('init-client-fields');
      const chevron = el.querySelector('.chevron');
      const isHidden = fields.classList.contains('hidden');
      fields.classList.toggle('hidden');
      chevron.textContent = isHidden ? '\u25BC' : '\u25B6';
    }
    function randHex(n) {
      return Array.from(crypto.getRandomValues(new Uint8Array(Math.ceil(n / 2)))).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, n);
    }
    function randBase64(byteLen) {
      const bytes = crypto.getRandomValues(new Uint8Array(byteLen));
      let s = '';
      bytes.forEach((b) => { s += String.fromCharCode(b); });
      return btoa(s);
    }
    function randUUID() {
      if (crypto.randomUUID) return crypto.randomUUID();
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      bytes[6] = (bytes[6] & 0x0f) | 0x40;
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
      return hex.slice(0,8) + '-' + hex.slice(8,12) + '-' + hex.slice(12,16) + '-' + hex.slice(16,20) + '-' + hex.slice(20);
    }
    function credentialForProtocol(proto) {
      if (proto === 'shadowsocks') return randBase64(16);
      if (proto === 'trojan' || proto === 'hysteria2') return randHex(16);
      return randUUID();
    }
    function protocolForClientModal() {
      const inboundId = Number(document.getElementById('client-inbound-id')?.value || 0);
      const inbound = (window._cachedInbounds || []).find((ib) => ib.id === inboundId);
      return inbound ? inbound.protocol : 'vless';
    }
    function makeFieldTools(id, secret) {
      const buttons = ['<button type="button" class="btn-mini" onclick="regenerateField(\'' + id + '\')">重新生成</button>'];
      if (secret) buttons.push('<button type="button" class="btn-mini" onclick="toggleSecretField(\'' + id + '\')">显示/隐藏</button>');
      return '<span style="display:inline-flex;gap:6px;align-items:center;margin-left:8px;flex-wrap:wrap">' + buttons.join('') + '</span>';
    }
    function regenerateField(id) {
      const el = document.getElementById(id);
      if (!el) return;
      if (id === 'inbound-reality-short-id' || id === 'ei-reality-short-id') el.value = randHex(8);
      else if (id === 'inbound-hy2-obfs-password' || id === 'ei-hy2-obfs-password') el.value = randHex(12);
      else if (id === 'inbound-uuid') el.value = credentialForProtocol(document.getElementById('inbound-protocol').value);
      else if (id === 'init-client-uuid') el.value = credentialForProtocol(document.getElementById('inbound-protocol').value);
      else if (id === 'client-uuid') el.value = credentialForProtocol(protocolForClientModal());
      else if (id === 'inbound-init-client-email' || id === 'init-client-email' || id === 'client-email') el.value = 'user@example.com';
      else if (id === 'inbound-ss-method' || id === 'ei-ss-method') el.value = '2022-blake3-aes-128-gcm';
      else el.value = randHex(8);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
    function regenerateFieldByName(name) {
      const el = document.querySelector('[name="'+name+'"]');
      if (el) { el.value = randCredential(); }
    }
    function toggleSecretField(id) {
      const el = document.getElementById(id);
      if (!el) return;
      el.type = el.type === 'password' ? 'text' : 'password';
    }
    function fillRandomDefaults(formEl) {
      const proto = document.getElementById('inbound-protocol').value;
      const sec = document.getElementById('inbound-security').value;
      const randHex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(Math.ceil(n/2)))).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, n);
      const randCredential = () => credentialForProtocol(proto);
      const setIfEmpty = (sel, val) => {
        const el = formEl.querySelector(sel);
        if (el && !el.value) el.value = val;
      };
      setIfEmpty('[name="uuid"]', randCredential());
      if (sec === 'reality') {
        setIfEmpty('[name="reality_dest"]', 'www.cloudflare.com:443');
        setIfEmpty('[name="reality_server_names"]', 'www.cloudflare.com');
        setIfEmpty('[name="reality_short_id"]', randHex(8));
      }
      if (sec === 'tls') {
        setIfEmpty('[name="tls_cert_file"]', '/etc/ssl/certs/fullchain.pem');
        setIfEmpty('[name="tls_key_file"]', '/etc/ssl/private/privkey.pem');
      }
      if (proto === 'hysteria2') {
        setIfEmpty('[name="hy2_obfs"]', 'salamander');
        setIfEmpty('[name="hy2_obfs_password"]', randHex(12));
      }
      if (proto === 'vless' || proto === 'trojan' || proto === 'vmess') {
        setIfEmpty('[name="reality_short_id"]', randHex(8));
      }
      if (proto === 'shadowsocks') {
        setIfEmpty('[name="ss_method"]', '2022-blake3-aes-128-gcm');
      }
      const initFields = document.getElementById('init-client-fields');
      if (initFields && !initFields.classList.contains('hidden')) {
        const emailEl = document.getElementById('init-client-email');
        if (emailEl && !emailEl.value) emailEl.value = 'user@example.com';
        const uuidEl = document.getElementById('init-client-uuid');
        if (uuidEl && !uuidEl.value) uuidEl.value = randCredential();
      }
      const credentialHelp = document.getElementById('init-client-credential-help');
      if (credentialHelp) {
        const label = proto === 'vless' || proto === 'vmess' ? 'UUID' : proto === 'shadowsocks' || proto === 'wireguard' ? '密码/密钥' : '密码';
        credentialHelp.textContent = '客户端凭据已自动生成为 ' + label + '，可以手动修改；不懂时保持默认即可。';
      }
    }

    async function saveCreateInbound() {
      const formEl = document.getElementById('create-inbound-form');
      const form = new FormData(formEl);
      const payload = Object.fromEntries(form.entries());
      payload.port = Number(payload.port);
      payload.hy2_up_mbps = Number(payload.hy2_up_mbps) || 0;
      payload.hy2_down_mbps = Number(payload.hy2_down_mbps) || 0;
      payload.tuic_zero_rtt = payload.tuic_zero_rtt === '1' || payload.tuic_zero_rtt === true;
      payload.hy2_up_mbps = Number(payload.hy2_up_mbps) || 0;
      payload.hy2_down_mbps = Number(payload.hy2_down_mbps) || 0;
      payload.wg_mtu = Number(payload.wg_mtu) || 0;
      payload.shadowtls_version = Number(payload.shadowtls_version) || 3;
      if (!payload.remark || !payload.port) { showToast('请填写备注和端口', 'error'); return; }
      // Port conflict check (client-side)
      const existingInbounds = window._cachedInbounds || [];
      const conflictInb = existingInbounds.find(ib => ib.port === payload.port);
      if (conflictInb) { showToast('端口 ' + payload.port + ' 已被入站 ' + (conflictInb.remark || conflictInb.id) + ' 使用', 'error'); return; }
      // Pack initial client if email is provided
      const initEmail = document.getElementById('init-client-email').value.trim();
      if (initEmail) {
        const initExpiryStr = document.getElementById('init-client-expiry').value;
        let initExpiry = 0;
        if (initExpiryStr) {
          initExpiry = Math.floor(new Date(initExpiryStr).getTime() / 1000);
        }
        payload.initial_client = {
          email: initEmail,
          uuid: document.getElementById('init-client-uuid').value.trim(),
          traffic_limit: Number(document.getElementById('init-client-traffic').value || 0),
          expiry_at: initExpiry
        };
      }
      delete payload.init_email;
      delete payload.init_traffic;
      const response = await fetch(apiPath('/api/inbounds'), {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      if (!response.ok) {
        showToast('创建入站失败', 'error');
        return;
      }
      formEl.reset();
      closeCreateInbound();
      showToast('入站创建成功', 'success');
      await loadInbounds();
    }

    document.getElementById('inbound-protocol').addEventListener('change', () => { applyProtocolPreset(document.getElementById('inbound-protocol').value); updateDynamicFields(); });
    document.getElementById('inbound-network').addEventListener('change', updateDynamicFields);
    document.getElementById('inbound-security').addEventListener('change', updateDynamicFields);
    updateDynamicFields();

    // === Xray status & apply ===
    async function fetchXrayStatus() {
      try {
        const res = await fetch(apiPath('/api/xray/status'));
        const data = await res.json();
        if (!data.installed) {
          document.getElementById('xray-status').textContent = '未安装';
          document.getElementById('xray-version').textContent = '-';
          document.getElementById('xray-memory').textContent = '-';
          document.getElementById('xray-uptime').textContent = '-';
          document.getElementById('xray-connections').textContent = '-';
          document.getElementById('xray-managed').textContent = data.managed ? '是' : '否';
          document.getElementById('xray-service').textContent = data.service || 'xray';
          document.getElementById('xray-config-path').textContent = data.config_path || '-';
          return;
        }
        document.getElementById('xray-status').textContent =
          data.status === 'running' ? '运行中' : (data.status === 'stopped' ? '已停止' : (data.status || '未知'));
        document.getElementById('xray-version').textContent = data.version || '-';
        document.getElementById('xray-memory').textContent = data.memory_rss_bytes ? formatBytes(data.memory_rss_bytes) : '-';
        document.getElementById('xray-uptime').textContent = data.uptime || '-';
        document.getElementById('xray-connections').textContent = data.active_connections != null ? data.active_connections.toString() : '-';
        document.getElementById('xray-managed').textContent = data.managed ? '是' : '否';
        document.getElementById('xray-service').textContent = data.service || 'xray';
        document.getElementById('xray-config-path').textContent = data.config_path || '-';
        // Hysteria2 is not supported by any current Xray version
        document.getElementById('xray-unsupported-warning').style.display = 'block';
      } catch (e) {
        document.getElementById('xray-status').textContent = '连接失败';
        document.getElementById('xray-memory').textContent = '-';
        document.getElementById('xray-uptime').textContent = '-';
        document.getElementById('xray-connections').textContent = '-';
      }
    }
    async function runCoreAction(core, action) {
      const label = core === 'xray' ? 'Xray' : 'Sing-box';
      const verb = action === 'install' ? '安装' : '卸载';
      const confirmed = await showConfirm('确认' + verb + ' ' + label + ' 核心？这会修改系统服务和二进制文件。');
      if (!confirmed) return;
      const resultId = core === 'xray' ? 'xray-result' : 'singbox-result';
      document.getElementById(resultId).innerHTML = renderNotice('正在' + verb, label + ' 核心操作执行中，请稍候。');
      const endpoint = {
        xray: {install: '/api/xray/install', uninstall: '/api/xray/uninstall'},
        singbox: {install: '/api/singbox/install', uninstall: '/api/singbox/uninstall'}
      }[core][action];
      try {
        const res = await fetch(apiPath(endpoint), {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({confirm:true, allow_system_changes:true})
        });
        const data = await res.json();
        if (!res.ok || data.status === 'failed') {
          throw new Error(data.output || data.error || '操作失败');
        }
        document.getElementById(resultId).innerHTML = renderNotice(verb + '完成', (data.output || label + ' 核心已' + verb).trim(), 'success');
        showToast(label + ' 核心' + verb + '完成', 'success');
        if (core === 'xray') await fetchXrayStatus(); else await fetchSingboxStatus();
      } catch (e) {
        document.getElementById(resultId).innerHTML = renderNotice(verb + '失败', e.message || '请检查系统权限、网络和服务状态。', 'error');
        showToast(label + ' 核心' + verb + '失败', 'error');
      }
    }
    function installXrayCore() { return runCoreAction('xray', 'install'); }
    function uninstallXrayCore() { return runCoreAction('xray', 'uninstall'); }
    function installSingboxCore() { return runCoreAction('singbox', 'install'); }
    function uninstallSingboxCore() { return runCoreAction('singbox', 'uninstall'); }

    async function applyXrayConfig() {
      document.getElementById('xray-result').innerHTML = renderNotice('正在应用', '正在写入 xray.json、执行配置校验并尝试重启 Xray 及 sing-box。');
      try {
        const res = await fetch(apiPath('/api/xray/apply'), {method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({confirm:true, allow_system_changes:true})});
        const data = await res.json();
        // New dual-kernel response: {xray: {...}, singbox: {...}}
        const xray = data.xray || data;
        const singboxResult = data.singbox;
        const commands = xray.commands_executed && xray.commands_executed.length ? '\n' + xray.commands_executed.join('\n') : '';
const singboxLine = singboxResult ? (singboxResult.applied ? '\nSing-box: ✅ 已应用' + (singboxResult.inbounds ? '(' + singboxResult.inbounds + ' 个入站)' : '') : singboxResult.reason === 'not_needed' ? '\nSing-box: ⏭ 无 sing-box 入站' : '\nSing-box: ❌ ' + (singboxResult.error || singboxResult.reason || '失败')) : '';
        if (xray.status && xray.status.startsWith('failed')) {
          const errDetail = xray.error_output ? '\n\n' + xray.error_output : '';
          document.getElementById('xray-result').innerHTML = renderNotice('应用失败', 'Xray 状态：' + xray.status + errDetail + commands + singboxLine, 'error');
          showToast('应用配置失败', 'error');
        } else {
          document.getElementById('xray-result').innerHTML = renderNotice('应用完成', 'Xray 状态：' + (xray.status || '完成') + commands + singboxLine, 'success');
          showToast('配置已应用', 'success');
        }
        await fetchXrayStatus();
      } catch (e) {
        document.getElementById('xray-result').innerHTML = renderNotice('应用失败', '请检查 Xray 配置目录、xray 命令和 systemd 服务状态。', 'error');
        showToast('应用配置失败', 'error');
      }
    }



    // === Xray config preview ===
    let _configVisible = false;
    async function previewXrayConfig() {
      const el = document.getElementById('xray-config-preview');
      const pre = document.getElementById('xray-config-json');
      if (_configVisible) return;
      _configVisible = true;
      try {
        const res = await fetch(apiPath('/api/xray/config'));
        const json = await res.json();
        pre.textContent = JSON.stringify(json, null, 2);
        el.style.display = '';
      } catch (e) {
        pre.textContent = '加载配置失败';
        el.style.display = '';
      }
    }
    function closeXrayConfig() {
      document.getElementById('xray-config-preview').style.display = 'none';
      _configVisible = false;
    }
    var _logsVisible = false;
    async function loadXrayLogs() {
      const el = document.getElementById('xray-logs-preview');
      const pre = document.getElementById('xray-logs-text');
      if (_logsVisible) return;
      _logsVisible = true;
      pre.textContent = '加载中...';
      el.style.display = '';
      try {
        const res = await fetch(apiPath('/api/xray/logs?lines=80'));
        const data = await res.json();
        pre.textContent = data.logs || '暂无日志';
      } catch (e) {
        pre.textContent = '加载日志失败';
      }
    }
    function closeXrayLogs() {
      document.getElementById('xray-logs-preview').style.display = 'none';
      _logsVisible = false;
    }

    // === Sing-box status & apply ===
    async function fetchSingboxStatus() {
      try {
        const res = await fetch(apiPath('/api/singbox/status'));
        const data = await res.json();
        if (!data.installed) {
          document.getElementById('singbox-status').textContent = '未安装';
          document.getElementById('singbox-version').textContent = '-';
          document.getElementById('singbox-memory').textContent = '-';
          document.getElementById('singbox-uptime').textContent = '-';
          document.getElementById('singbox-connections').textContent = '-';
          return;
        }
        document.getElementById('singbox-status').textContent =
          data.status === 'running' ? '运行中' : (data.status === 'stopped' ? '已停止' : data.status);
        document.getElementById('singbox-version').textContent = data.version || '-';
        document.getElementById('singbox-memory').textContent = data.memory_rss_bytes ? formatBytes(data.memory_rss_bytes) : '-';
        document.getElementById('singbox-uptime').textContent = data.uptime || '-';
        document.getElementById('singbox-connections').textContent = data.active_connections != null ? data.active_connections.toString() : '-';
      } catch (e) {
        document.getElementById('singbox-status').textContent = '连接失败';
        document.getElementById('singbox-memory').textContent = '-';
        document.getElementById('singbox-uptime').textContent = '-';
        document.getElementById('singbox-connections').textContent = '-';
      }
    }
    async function applySingboxConfig() {
      document.getElementById('singbox-result').innerHTML = renderNotice('正在应用', '正在写入 sing-box 配置并尝试重启服务。');
      try {
        const res = await fetch(apiPath('/api/singbox/apply'), {method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({confirm:true, allow_system_changes:true})});
        const data = await res.json();
        if (data.applied) {
          document.getElementById('singbox-result').innerHTML = renderNotice('应用完成', 'Sing-box 配置已应用' + (data.inbounds ? '（' + data.inbounds + ' 个入站）' : ''), 'success');
          showToast('Sing-box 配置已应用', 'success');
        } else {
          document.getElementById('singbox-result').innerHTML = renderNotice('应用失败', data.error || data.reason || '未知错误', 'error');
          showToast('Sing-box 应用失败', 'error');
        }
        await fetchSingboxStatus();
      } catch (e) {
        document.getElementById('singbox-result').innerHTML = renderNotice('应用失败', '请求失败，请检查网络连接和服务状态。', 'error');
        showToast('Sing-box 应用失败', 'error');
      }
    }
    // === Sing-box config preview ===
    let _singboxConfigVisible = false;
    async function previewSingboxConfig() {
      const el = document.getElementById('singbox-config-preview');
      const pre = document.getElementById('singbox-config-json');
      if (_singboxConfigVisible) return;
      _singboxConfigVisible = true;
      try {
        const res = await fetch(apiPath('/api/singbox/config'));
        const text = await res.text();
        pre.textContent = text;
        el.style.display = '';
      } catch (e) {
        pre.textContent = '加载配置失败';
        el.style.display = '';
      }
    }
    function closeSingboxConfig() {
      document.getElementById('singbox-config-preview').style.display = 'none';
      _singboxConfigVisible = false;
    }

    // === Sing-box logs ===
    var _singboxLogsVisible = false;
    async function loadSingboxLogs() {
      const el = document.getElementById('singbox-logs-preview');
      const pre = document.getElementById('singbox-logs-text');
      if (_singboxLogsVisible) return;
      _singboxLogsVisible = true;
      pre.textContent = '加载中...';
      el.style.display = '';
      try {
        const res = await fetch(apiPath('/api/singbox/logs?lines=80'));
        const data = await res.json();
        pre.textContent = data.logs || '暂无日志';
      } catch (e) {
        pre.textContent = '加载日志失败';
      }
    }
    function closeSingboxLogs() {
      document.getElementById('singbox-logs-preview').style.display = 'none';
      _singboxLogsVisible = false;
    }

    // === Settings ===
    async function loadSettings() {
      try {
        const res = await fetch(apiPath('/api/settings'));
        if (!res.ok) { throw new Error('not available'); }
        const data = await res.json();
        document.getElementById('set-panel-port').value = data.panel_port || '';
        document.getElementById('set-username').value = data.panel_username || '';
        document.getElementById('set-password').value = '';
        document.getElementById('set-xray-config-path').value = data.xray_config_path || '';
        document.getElementById('set-web-path').value = data.web_base_path || '';
        document.getElementById('set-cert-domain').value = data.cert_domain || '';
        document.getElementById('set-cert-email').value = data.cert_email || '';
        if (data.database_path) {
          document.getElementById('settings-status').innerHTML = renderNotice('数据库', data.database_path + (data.has_password ? ' | 密码已设置' : ' | 无密码'), 'success');
        }
        fetchCertStatus();
        fetchServiceStatus();
      } catch (e) {
        document.getElementById('settings-status').innerHTML = renderNotice('设置不可用', '需要在 panel.json 配置文件下运行，或检查配置目录是否已传入。', 'error');
      }
    }
    async function fetchCertStatus() {
      try {
        const res = await fetch(apiPath('/api/cert/status'));
        if (!res.ok) { return; }
        const data = await res.json();
        document.getElementById('cert-status-area').style.display = '';
        const label = document.getElementById('cert-status-label');
        const pathEl = document.getElementById('cert-path-label');
        if (data.issued) {
          label.textContent = '✓ 已签发';
          label.style.color = 'var(--accent2)';
          pathEl.textContent = '证书：' + (data.cert_path || '') + ' | 密钥：' + (data.key_path || '');
        } else if (data.domain) {
          label.textContent = '待获取（域名已配置）';
          label.style.color = 'var(--amber)';
          pathEl.textContent = '';
        } else {
          label.textContent = '未配置';
          label.style.color = '';
          pathEl.textContent = '';
        }
      } catch (e) {}
    }
    async function issueCert() {
      const domain = document.getElementById('set-cert-domain').value.trim();
      const email = document.getElementById('set-cert-email').value.trim();
      if (!domain || !email) {
        showToast('请先填写域名和邮箱', 'error');
        return;
      }
      const btn = document.getElementById('btn-issue-cert');
      btn.disabled = true;
      btn.textContent = '签发中…';
      document.getElementById('cert-status-label').textContent = '签发中，请等待…';
      try {
        const res = await fetch(apiPath('/api/cert/issue'), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({domain, email})
        });
        const data = await res.json();
        if (res.ok && data.status === 'issued') {
          showToast('证书获取成功', 'success');
          fetchCertStatus();
        } else {
          showToast('签发失败：' + (data.detail || data.error || '未知错误'), 'error');
          document.getElementById('cert-status-label').textContent = '签发失败';
        }
      } catch (e) {
        showToast('签发失败：网络错误', 'error');
        document.getElementById('cert-status-label').textContent = '签发失败';
      }
      btn.disabled = false;
      btn.textContent = '获取证书';
    }
    async function saveSettings() {
      var btn = document.querySelector('[onclick*="saveSettings"]');
      if (btn.disabled) return;
      btn.disabled = true;
      btn.textContent = '保存中...';
      const data = {
        panel_port: parseInt(document.getElementById('set-panel-port').value) || 0,
        panel_username: document.getElementById('set-username').value.trim(),
        panel_password: document.getElementById('set-password').value,
        xray_config_path: document.getElementById('set-xray-config-path').value.trim(),
        web_base_path: document.getElementById('set-web-path').value.trim() || '/',
        cert_domain: document.getElementById('set-cert-domain').value.trim(),
        cert_email: document.getElementById('set-cert-email').value.trim(),
      };
      if (!data.panel_port) { showToast('请输入面板端口', 'error'); return; }
      try {
        const res = await fetch(apiPath('/api/settings'), {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(data)
        });
        if (!res.ok) { showToast('保存设置失败', 'error'); return; }
        showToast('设置已保存，重启服务后生效', 'success');
        document.getElementById('set-password').value = '';
        await loadSettings();
      } catch (e) {
        showToast('保存设置失败', 'error');
      }
      btn.disabled = false;
      btn.textContent = '保存设置';
    }
    async function restartService() {
      if (!await showConfirm('确认重启 MiGate 服务？页面将暂时无法访问，重启后自动重试恢复。')) return;
      const btn = document.querySelector('button.danger');
      btn.disabled = true;
      btn.textContent = '重启中…';
      try {
        const res = await fetch(apiPath('/api/restart'), { method: 'POST' });
        if (!res.ok) { showToast('重启失败', 'error'); btn.disabled = false; btn.textContent = '重启服务'; return; }
        showToast('正在重启 MiGate 服务…', 'success');
        // Retry reload until the page comes back up
        let retries = 0;
        const maxRetries = 30;
        const retryDelay = 1500;
        function tryReload() {
          retries++;
          if (retries >= maxRetries) {
            showToast('重启超时，请手动刷新', 'error');
            btn.disabled = false;
            btn.textContent = '重启服务';
            return;
          }
          setTimeout(function() { location.reload(true); }, retryDelay);
        }
        setTimeout(tryReload, 1000);
      } catch (e) {
        showToast('重启请求失败', 'error');
        btn.disabled = false;
        btn.textContent = '重启服务';
      }
    }

    async function fetchServiceStatus() {
      try {
        const res = await fetch(apiPath('/api/service/status'));
        if (!res.ok) { throw new Error('not available'); }
        const data = await res.json();
        const badge = document.getElementById('svc-status-badge');
        const detail = document.getElementById('svc-status-detail');
        if (data.status === 'active') {
          badge.innerHTML = '<span style="color:var(--accent2)">●</span> 运行中';
          badge.style.background = 'rgba(0,180,0,0.1)';
          detail.textContent = data.detail || '';
        } else if (data.status === 'inactive' || data.status === 'failed') {
          badge.innerHTML = '<span style="color:var(--danger)">●</span> ' + (data.status === 'failed' ? '异常' : '未运行');
          badge.style.background = 'rgba(220,40,40,0.1)';
          detail.textContent = '';
        } else {
          badge.textContent = '未知';
          badge.style.background = 'var(--surface-subtle)';
          detail.textContent = '非 systemd 环境或服务未安装';
        }
      } catch (e) {
        document.getElementById('svc-status-badge').textContent = '不可用';
        document.getElementById('svc-status-detail').textContent = '无法查询服务状态';
      }
    }

    // === Version check ===
    async function checkVersion() {
      try {
        const res = await fetch(apiPath('/api/version'));
        const data = await res.json();
        const current = data.version || 'dev';
        if (current === 'dev') return;
        // Check GitHub for latest release
        const ghRes = await fetch('https://api.github.com/repos/imzyb/MiGate/releases/latest');
        if (!ghRes.ok) return;
        const gh = await ghRes.json();
        const latest = (gh.tag_name || '').replace(/^v/, '');
        const cur = current.replace(/^v/, '');
        if (latest && latest !== cur) {
          const banner = document.getElementById('version-banner');
          banner.innerHTML = '🚀 新版本 <strong>v' + escapeHtml(latest) + '</strong> 已发布（当前 v' + escapeHtml(cur) + '）。查看 <a href="' + gh.html_url + '" target="_blank">更新日志</a>';
          banner.style.display = 'block';
        }
      } catch (e) { /* silent */ }
    }
    checkVersion();

    fetchXrayStatus();
    loadSettings();
