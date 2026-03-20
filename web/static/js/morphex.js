/* ============================================================
   MORPHEX — Frontend JavaScript (Vanilla, No Frameworks)
   Complete SPA: Router, API Client, Charts, Pages
   ============================================================ */

(function () {
    "use strict";

    /* -------------------------------------------------------
       Color Tokens
    ------------------------------------------------------- */
    var COLORS = {
        copper: '#d4956a', emerald: '#3ecf8e', ember: '#f0623d',
        amber: '#f0b232', iris: '#8b7cf6', sky: '#5ba3f5'
    };

    /* -------------------------------------------------------
       Format Helpers
    ------------------------------------------------------- */

    function timeAgo(dateStr) {
        var now = Date.now();
        var then = new Date(dateStr).getTime();
        if (isNaN(then)) return '—';
        var diff = Math.max(0, now - then);
        var sec = Math.floor(diff / 1000);
        if (sec < 60) return sec + 's ago';
        var min = Math.floor(sec / 60);
        if (min < 60) return min + 'm ago';
        var hr = Math.floor(min / 60);
        if (hr < 24) return hr + 'h ago';
        var day = Math.floor(hr / 24);
        if (day < 30) return day + 'd ago';
        return new Date(dateStr).toLocaleDateString();
    }

    function formatDuration(ms) {
        if (ms == null) return '—';
        if (ms < 1000) return Math.round(ms) + 'ms';
        if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
        return (ms / 60000).toFixed(1) + 'm';
    }

    function formatBytes(bytes) {
        if (bytes == null || bytes === 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    }

    function formatNumber(n) {
        if (n == null) return '0';
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }

    function severityColor(sev) {
        if (!sev) return 'var(--text-muted)';
        var s = sev.toLowerCase();
        if (s === 'critical') return 'var(--accent-red)';
        if (s === 'high') return 'var(--accent-amber)';
        if (s === 'medium') return 'var(--accent-blue)';
        if (s === 'low') return 'var(--accent-green)';
        return 'var(--text-muted)';
    }

    function severityClass(sev) {
        if (!sev) return '';
        return sev.toLowerCase();
    }

    function provenanceColor(prov) {
        if (!prov) return COLORS.sky;
        var p = prov.toLowerCase();
        if (p === 'environment') return COLORS.emerald;
        if (p === 'config' || p === 'configuration') return COLORS.amber;
        if (p === 'source' || p === 'source_code') return COLORS.iris;
        if (p === 'infrastructure') return COLORS.copper;
        if (p === 'vcs' || p === 'version_control') return COLORS.ember;
        return COLORS.sky;
    }

    function animateCounter(el, from, to, duration) {
        var start = performance.now();
        duration = duration || 800;
        function tick(now) {
            var elapsed = now - start;
            var progress = Math.min(elapsed / duration, 1);
            var eased = 1 - Math.pow(1 - progress, 3);
            var current = Math.round(from + (to - from) * eased);
            el.textContent = formatNumber(current);
            if (progress < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function truncate(str, max) {
        if (!str) return '';
        return str.length > max ? str.slice(0, max) + '…' : str;
    }

    function copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(function () {
                showToast('Copied to clipboard', 'success', 2000);
            });
        } else {
            var ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
            showToast('Copied to clipboard', 'success', 2000);
        }
    }

    /* -------------------------------------------------------
       State Management
    ------------------------------------------------------- */

    var state = {
        currentPage: 'dashboard',
        apiKey: localStorage.getItem('morphex_api_key') || '',
        theme: localStorage.getItem('morphex_theme') || 'dark',
        stats: null,
        scans: [],
        currentScan: null,
        findings: [],
        metricsData: null,
        scanInProgress: false,
        scanProgress: null,
        toasts: [],
        refreshTimers: []
    };

    function clearRefreshTimers() {
        state.refreshTimers.forEach(function (t) { clearInterval(t); clearTimeout(t); });
        state.refreshTimers = [];
    }

    /* -------------------------------------------------------
       Toast System
    ------------------------------------------------------- */

   function showToast(message, type, duration) {
       type = type || 'info';
       duration = duration || 5000;
        var container = document.getElementById('toast-container');
        if (!container) return;

        var icons = { info: 'ℹ', success: '✓', warning: '⚠', error: '✗' };
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.innerHTML = '<span class="toast-icon">' + (icons[type] || 'ℹ') + '</span>' +
            '<span>' + escapeHtml(message) + '</span>';
        container.appendChild(toast);

        var timer = setTimeout(function () {
            toast.classList.add('toast-exit');
            setTimeout(function () {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, duration);

        toast.addEventListener('click', function () {
            clearTimeout(timer);
            toast.classList.add('toast-exit');
            setTimeout(function () {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        });
    }

    /* -------------------------------------------------------
       Modal System
    ------------------------------------------------------- */

    function showModal(title, contentHtml, actions) {
        var existing = document.getElementById('morphexModal');
        if (existing) existing.parentNode.removeChild(existing);

        var backdrop = document.createElement('div');
        backdrop.id = 'morphexModal';
        backdrop.style.cssText = 'position:fixed;inset:0;z-index:300;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);animation:fadeIn .2s ease';

        var card = document.createElement('div');
        card.className = 'glass-card';
        card.style.cssText = 'width:90%;max-width:560px;max-height:80vh;overflow:auto;animation:scaleIn .25s ease';

        var header = '<div class="card-header"><span>' + escapeHtml(title) + '</span>' +
            '<button class="btn-icon" id="modalCloseBtn" style="width:28px;height:28px;font-size:.9rem">✕</button></div>';
        var body = '<div class="card-body">' + contentHtml + '</div>';

        var footer = '';
        if (actions && actions.length) {
            footer = '<div style="padding:0 20px 16px;display:flex;gap:8px;justify-content:flex-end">';
            actions.forEach(function (a) {
                footer += '<button class="btn ' + (a.cls || 'btn-secondary') + ' btn-sm" data-action="' + a.id + '">' + escapeHtml(a.label) + '</button>';
            });
            footer += '</div>';
        }

        card.innerHTML = header + body + footer;
        backdrop.appendChild(card);
        document.body.appendChild(backdrop);

        function closeModal() {
            backdrop.style.opacity = '0';
            setTimeout(function () {
                if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop);
            }, 200);
        }

        backdrop.addEventListener('click', function (e) {
            if (e.target === backdrop) closeModal();
        });
        card.querySelector('#modalCloseBtn').addEventListener('click', closeModal);

        if (actions) {
            actions.forEach(function (a) {
                var btn = card.querySelector('[data-action="' + a.id + '"]');
                if (btn && a.handler) btn.addEventListener('click', function () {
                    a.handler();
                    closeModal();
                });
            });
        }

        document.addEventListener('keydown', function handler(e) {
            if (e.key === 'Escape') {
                closeModal();
                document.removeEventListener('keydown', handler);
            }
        });

        return closeModal;
    }

    /* -------------------------------------------------------
       Skeleton Loading
    ------------------------------------------------------- */

    function showSkeleton(container, rows) {
        rows = rows || 3;
        var html = '';
        for (var i = 0; i < rows; i++) {
            var h = 40 + Math.random() * 60;
            html += '<div class="shimmer-block shimmer" style="height:' + h + 'px;margin-bottom:12px;border-radius:var(--radius-md)"></div>';
        }
        container.innerHTML = html;
    }

    /* -------------------------------------------------------
       API Client
    ------------------------------------------------------- */

    function MorphexAPI() {
        this.baseURL = '';
        this.apiKey = localStorage.getItem('morphex_api_key') || '';
    }

    MorphexAPI.prototype.request = function (method, path, body) {
        var self = this;
        var headers = { 'Content-Type': 'application/json' };
        if (self.apiKey) headers['X-API-Key'] = self.apiKey;
        var opts = { method: method, headers: headers };
        if (body) opts.body = JSON.stringify(body);
        return fetch(self.baseURL + path, opts).then(function (res) {
            if (res.status === 401) {
                showToast('Authentication failed — check API key', 'error');
                router.navigate('/settings');
                throw new Error('Unauthorized');
            }
            if (!res.ok) {
                return res.text().then(function (t) { throw new Error(t || 'Request failed'); });
            }
            var ct = res.headers.get('content-type') || '';
            if (ct.indexOf('application/json') !== -1) return res.json();
            return res.text();
        });
    };

    MorphexAPI.prototype.scanContent = function (content, opts) {
        return this.request('POST', '/api/v1/scan/content', Object.assign({ content: content }, opts || {}));
    };
    MorphexAPI.prototype.scanDirectory = function (path, opts) {
        return this.request('POST', '/api/v1/scan/directory', Object.assign({ path: path }, opts || {}));
    };
    MorphexAPI.prototype.scanGit = function (repoPath, opts) {
        return this.request('POST', '/api/v1/scan/git', Object.assign({ repo_path: repoPath }, opts || {}));
    };
    MorphexAPI.prototype.classify = function (value, varName) {
        return this.request('POST', '/api/v1/analyze/classify', { value: value, var_name: varName });
    };
    MorphexAPI.prototype.getStats = function () {
        return this.request('GET', '/api/v1/dashboard/stats');
    };
    MorphexAPI.prototype.getTrends = function () {
        return this.request('GET', '/api/v1/dashboard/trends');
    };
    MorphexAPI.prototype.getScans = function (limit) {
        return this.request('GET', '/api/v1/scans?limit=' + (limit || 50));
    };
    MorphexAPI.prototype.getScan = function (id) {
        return this.request('GET', '/api/v1/scans/' + id);
    };
    MorphexAPI.prototype.getScanFindings = function (id) {
        return this.request('GET', '/api/v1/scans/' + id + '/findings');
    };
    MorphexAPI.prototype.health = function () {
        return this.request('GET', '/api/v1/health');
    };
    MorphexAPI.prototype.version = function () {
        return this.request('GET', '/api/v1/version');
    };
    MorphexAPI.prototype.metrics = function () {
        var self = this;
        var headers = {};
        if (self.apiKey) headers['X-API-Key'] = self.apiKey;
        return fetch('/api/v1/metrics', { headers: headers }).then(function (r) { return r.text(); });
    };
    MorphexAPI.prototype.streamScan = function (scanId, onEvent) {
        var url = '/api/v1/stream/' + scanId;
        var source = new EventSource(url);
        source.onmessage = function (e) {
            try { onEvent(JSON.parse(e.data)); } catch (err) { onEvent({ raw: e.data }); }
        };
        source.onerror = function () { source.close(); };
        return source;
    };

    /* -------------------------------------------------------
       Router (hash-based SPA)
    ------------------------------------------------------- */

    function Router() {
        this.routes = [];
        this.notFound = null;
    }

    Router.prototype.on = function (pattern, handler) {
        var paramNames = [];
        var regexStr = pattern.replace(/:([^/]+)/g, function (_, name) {
            paramNames.push(name);
            return '([^/]+)';
        });
        this.routes.push({
            regex: new RegExp('^' + regexStr + '$'),
            paramNames: paramNames,
            handler: handler
        });
    };

    Router.prototype.resolve = function () {
        var hash = location.hash.slice(1) || '/';
        for (var i = 0; i < this.routes.length; i++) {
            var route = this.routes[i];
            var match = hash.match(route.regex);
            if (match) {
                var params = {};
                route.paramNames.forEach(function (name, idx) {
                    params[name] = decodeURIComponent(match[idx + 1]);
                });
                route.handler(params);
                return;
            }
        }
        if (this.notFound) this.notFound();
    };

    Router.prototype.start = function () {
        var self = this;
        window.addEventListener('hashchange', function () { self.resolve(); });
        self.resolve();
    };

    Router.prototype.navigate = function (path) {
        location.hash = '#' + path;
    };

    var router = new Router();

    /* -------------------------------------------------------
       Navigation Helpers
    ------------------------------------------------------- */

   function updateNav(page) {
       state.currentPage = page;
        var links = document.querySelectorAll('.nav-item');
        links.forEach(function (link) {
            var dp = link.getAttribute('data-page');
            if (dp === page) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });
        var breadcrumb = document.getElementById('breadcrumb');
        if (breadcrumb) {
            var names = { dashboard: 'Dashboard', scan: 'New Scan', findings: 'Findings', metrics: 'Metrics', history: 'History', settings: 'Settings' };
            breadcrumb.textContent = names[page] || page;
        }
    }

    function getMainContent() {
        var el = document.getElementById('page-content');
        if (el) animatePageTransition(el);
        return el;
    }

    /* -------------------------------------------------------
       SVG Chart Library
    ------------------------------------------------------- */

    function svgEl(tag, attrs, children) {
        var el = document.createElementNS('http://www.w3.org/2000/svg', tag);
        if (attrs) {
            Object.keys(attrs).forEach(function (k) {
                el.setAttribute(k, attrs[k]);
            });
        }
        if (children) {
            if (typeof children === 'string') {
                el.textContent = children;
            } else if (Array.isArray(children)) {
                children.forEach(function (c) { if (c) el.appendChild(c); });
            }
        }
        return el;
    }

    function bezierPath(points) {
        if (points.length < 2) return '';
        var d = 'M ' + points[0][0] + ' ' + points[0][1];
        for (var i = 0; i < points.length - 1; i++) {
            var x0 = points[i][0], y0 = points[i][1];
            var x1 = points[i + 1][0], y1 = points[i + 1][1];
            var cpx = (x0 + x1) / 2;
            d += ' C ' + cpx + ' ' + y0 + ', ' + cpx + ' ' + y1 + ', ' + x1 + ' ' + y1;
        }
        return d;
    }

    /* --- Time Series Chart --- */
    function renderTimeSeries(container, data, options) {
        container.innerHTML = '';
        if (!data || !data.length) {
            container.innerHTML = '<div class="empty-state" style="padding:30px"><div class="empty-state-icon">📈</div><div class="empty-state-text">No data available</div></div>';
            return;
        }
        options = options || {};
        var color = options.color || 'var(--accent-blue)';
        var rawColor = options.rawColor || '#00d4ff';
        var height = options.height || 200;
        var width = options.width || 600;
        var showGrid = options.showGrid !== false;
        var showArea = options.showArea !== false;
        var label = options.label || '';

        var padL = 50, padR = 20, padT = 20, padB = 35;
        var chartW = width - padL - padR;
        var chartH = height - padT - padB;

        var values = data.map(function (d) { return d.value; });
        var minV = Math.min.apply(null, values);
        var maxV = Math.max.apply(null, values);
        if (minV === maxV) { minV -= 1; maxV += 1; }
        var rangeV = maxV - minV;

        function scaleX(i) { return padL + (i / (data.length - 1)) * chartW; }
        function scaleY(v) { return padT + chartH - ((v - minV) / rangeV) * chartH; }

        var svg = svgEl('svg', { viewBox: '0 0 ' + width + ' ' + height, preserveAspectRatio: 'xMidYMid meet', style: 'width:100%;display:block' });

        var defs = svgEl('defs');
        var grad = svgEl('linearGradient', { id: 'tsGrad_' + label.replace(/\W/g, ''), x1: '0', y1: '0', x2: '0', y2: '1' });
        grad.appendChild(svgEl('stop', { offset: '0%', 'stop-color': rawColor, 'stop-opacity': '0.4' }));
        grad.appendChild(svgEl('stop', { offset: '100%', 'stop-color': rawColor, 'stop-opacity': '0.02' }));
        defs.appendChild(grad);
        svg.appendChild(defs);

        if (showGrid) {
            var gridSteps = 5;
            for (var gi = 0; gi <= gridSteps; gi++) {
                var gy = padT + (gi / gridSteps) * chartH;
                svg.appendChild(svgEl('line', { x1: padL, y1: gy, x2: width - padR, y2: gy, stroke: 'var(--border-subtle)', 'stroke-dasharray': '4 4', 'stroke-width': '0.5' }));
                var lv = maxV - (gi / gridSteps) * rangeV;
                svg.appendChild(svgEl('text', { x: padL - 6, y: gy + 3, 'text-anchor': 'end', fill: 'var(--text-muted)', 'font-size': '9', 'font-family': 'var(--font-mono)' }, formatNumber(Math.round(lv))));
            }
        }

        var points = [];
        for (var i = 0; i < data.length; i++) {
            points.push([scaleX(i), scaleY(data[i].value)]);
        }

        var pathD = bezierPath(points);

        if (showArea) {
            var areaD = pathD + ' L ' + points[points.length - 1][0] + ' ' + (padT + chartH) + ' L ' + points[0][0] + ' ' + (padT + chartH) + ' Z';
            svg.appendChild(svgEl('path', { d: areaD, fill: 'url(#tsGrad_' + label.replace(/\W/g, '') + ')' }));
        }

        svg.appendChild(svgEl('path', { d: pathD, fill: 'none', stroke: rawColor, 'stroke-width': '2.5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }));

        var step = Math.max(1, Math.floor(data.length / 6));
        for (var xi = 0; xi < data.length; xi += step) {
            var timeStr = '';
            if (data[xi].time) {
                var d = new Date(data[xi].time);
                timeStr = d.getMonth() + 1 + '/' + d.getDate();
            } else {
                timeStr = String(xi);
            }
            svg.appendChild(svgEl('text', { x: scaleX(xi), y: height - 6, 'text-anchor': 'middle', fill: 'var(--text-muted)', 'font-size': '9', 'font-family': 'var(--font-mono)' }, timeStr));
        }

        for (var di = 0; di < data.length; di++) {
            var dot = svgEl('circle', { cx: points[di][0], cy: points[di][1], r: '3', fill: rawColor, 'class': 'chart-dot', 'data-idx': di });
            svg.appendChild(dot);
        }

        container.appendChild(svg);

        var tooltip = document.createElement('div');
        tooltip.className = 'chart-tooltip';
        container.style.position = 'relative';
        container.appendChild(tooltip);

        svg.addEventListener('mousemove', function (e) {
            var rect = svg.getBoundingClientRect();
            var mx = e.clientX - rect.left;
            var ratio = mx / rect.width;
            var idx = Math.round(ratio * (data.length - 1));
            idx = Math.max(0, Math.min(data.length - 1, idx));
            var item = data[idx];
            var timeLabel = item.time ? new Date(item.time).toLocaleString() : '';
            tooltip.textContent = (timeLabel ? timeLabel + ': ' : '') + formatNumber(item.value);
            tooltip.classList.add('visible');
            tooltip.style.left = (ratio * 100) + '%';
            tooltip.style.top = '0';
        });

        svg.addEventListener('mouseleave', function () {
            tooltip.classList.remove('visible');
        });
    }

    /* --- Donut Chart --- */
    function renderDonut(container, data, options) {
        container.innerHTML = '';
        if (!data || !data.length) {
            container.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-icon">🍩</div><div class="empty-state-text">No data</div></div>';
            return;
        }
        options = options || {};
        var size = options.size || 140;
        var strokeW = options.strokeWidth || 20;
        var total = data.reduce(function (s, d) { return s + d.value; }, 0);

        var wrap = document.createElement('div');
        wrap.className = 'donut-chart-wrap';

        var svgSize = size;
        var center = svgSize / 2;
        var radius = (svgSize - strokeW) / 2;
        var circumference = 2 * Math.PI * radius;

        var svg = svgEl('svg', { viewBox: '0 0 ' + svgSize + ' ' + svgSize, width: svgSize, height: svgSize, style: 'flex-shrink:0' });

        svg.appendChild(svgEl('circle', { cx: center, cy: center, r: radius, fill: 'none', stroke: 'var(--bg-input)', 'stroke-width': strokeW }));

        var offset = 0;
        data.forEach(function (item) {
            var pct = total > 0 ? item.value / total : 0;
            var dashLen = pct * circumference;
            var dashGap = circumference - dashLen;
            var circle = svgEl('circle', {
                cx: center, cy: center, r: radius, fill: 'none',
                stroke: item.color || 'var(--accent-blue)',
                'stroke-width': strokeW,
                'stroke-dasharray': dashLen + ' ' + dashGap,
                'stroke-dashoffset': -offset,
                transform: 'rotate(-90 ' + center + ' ' + center + ')',
                'stroke-linecap': 'round',
                style: 'transition: stroke-dasharray 1s ease'
            });
            svg.appendChild(circle);
            offset += dashLen;
        });

        svg.appendChild(svgEl('text', {
            x: center, y: center - 4, 'text-anchor': 'middle', fill: 'var(--text-primary)',
            'font-size': '18', 'font-weight': '700', 'font-family': 'var(--font-mono)'
        }, String(total)));
        svg.appendChild(svgEl('text', {
            x: center, y: center + 12, 'text-anchor': 'middle', fill: 'var(--text-muted)',
            'font-size': '9', 'font-weight': '500'
        }, 'TOTAL'));

        wrap.appendChild(svg);

        var legend = document.createElement('div');
        legend.className = 'donut-legend';
        data.forEach(function (item) {
            var row = document.createElement('div');
            row.className = 'legend-item';
            row.innerHTML = '<span class="legend-dot" style="background:' + item.color + '"></span>' +
                '<span>' + escapeHtml(item.label) + '</span>' +
                '<span class="legend-value">' + item.value + '</span>';
            legend.appendChild(row);
        });
        wrap.appendChild(legend);
        container.appendChild(wrap);
    }

    /* --- Bar Chart --- */
    function renderBarChart(container, data, options) {
        container.innerHTML = '';
        if (!data || !data.length) {
            container.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-icon">📊</div><div class="empty-state-text">No data</div></div>';
            return;
        }
        options = options || {};
        var sorted = data.slice().sort(function (a, b) { return b.value - a.value; });
        var maxVal = sorted[0].value || 1;

        sorted.forEach(function (item) {
            var row = document.createElement('div');
            row.className = 'bar-row';
            var pct = Math.max(2, (item.value / maxVal) * 100);
            var barColor = item.color || 'linear-gradient(90deg, var(--accent-blue), var(--accent-green))';
            row.innerHTML = '<span class="bar-label" title="' + escapeHtml(item.label) + '">' + escapeHtml(item.label) + '</span>' +
                '<div class="bar-track"><div class="bar-fill" style="width:' + pct + '%;background:' + barColor + '"></div></div>' +
                '<span class="bar-count">' + item.value + '</span>';
            container.appendChild(row);
        });
    }

    /* --- Sparkline --- */
    function renderSparkline(container, data, color, width, height) {
        container.innerHTML = '';
        if (!data || data.length < 2) return;
        width = width || 120;
        height = height || 32;
        color = color || '#00d4ff';

        var minV = Math.min.apply(null, data);
        var maxV = Math.max.apply(null, data);
        if (minV === maxV) { minV -= 1; maxV += 1; }
        var rangeV = maxV - minV;

        var points = data.map(function (v, i) {
            return [
                (i / (data.length - 1)) * width,
                height - ((v - minV) / rangeV) * (height - 4) - 2
            ];
        });

        var pathD = bezierPath(points);

        var svg = svgEl('svg', { viewBox: '0 0 ' + width + ' ' + height, width: width, height: height, style: 'display:block' });
        svg.appendChild(svgEl('path', { d: pathD, fill: 'none', stroke: color, 'stroke-width': '2', 'stroke-linecap': 'round' }));
        container.appendChild(svg);
    }

    /* --- Stacked Area Chart (for metrics) --- */
    function renderStackedArea(container, seriesArr, options) {
        container.innerHTML = '';
        if (!seriesArr || !seriesArr.length || !seriesArr[0].data || !seriesArr[0].data.length) {
            container.innerHTML = '<div class="empty-state" style="padding:30px"><div class="empty-state-icon">📈</div><div class="empty-state-text">No data available</div></div>';
            return;
        }
        options = options || {};
        var height = options.height || 200;
        var width = options.width || 600;
        var padL = 50, padR = 20, padT = 20, padB = 35;
        var chartW = width - padL - padR;
        var chartH = height - padT - padB;
        var len = seriesArr[0].data.length;

        var stacked = [];
        for (var i = 0; i < len; i++) {
            var cumul = 0;
            var entry = [];
            for (var s = 0; s < seriesArr.length; s++) {
                cumul += (seriesArr[s].data[i] || { value: 0 }).value || 0;
                entry.push(cumul);
            }
            stacked.push(entry);
        }

        var maxV = 0;
        stacked.forEach(function (e) { var top = e[e.length - 1]; if (top > maxV) maxV = top; });
        if (maxV === 0) maxV = 1;

        function scaleX(idx) { return padL + (idx / (len - 1)) * chartW; }
        function scaleY(v) { return padT + chartH - (v / maxV) * chartH; }

        var svg = svgEl('svg', { viewBox: '0 0 ' + width + ' ' + height, preserveAspectRatio: 'xMidYMid meet', style: 'width:100%;display:block' });

        for (var si = seriesArr.length - 1; si >= 0; si--) {
            var topPts = [];
            var botPts = [];
            for (var j = 0; j < len; j++) {
                topPts.push([scaleX(j), scaleY(stacked[j][si])]);
                var below = si > 0 ? stacked[j][si - 1] : 0;
                botPts.push([scaleX(j), scaleY(below)]);
            }
            var d = 'M ' + topPts[0][0] + ' ' + topPts[0][1];
            for (var k = 1; k < topPts.length; k++) {
                d += ' L ' + topPts[k][0] + ' ' + topPts[k][1];
            }
            for (var k2 = botPts.length - 1; k2 >= 0; k2--) {
                d += ' L ' + botPts[k2][0] + ' ' + botPts[k2][1];
            }
            d += ' Z';
            svg.appendChild(svgEl('path', { d: d, fill: seriesArr[si].color || 'var(--accent-blue)', opacity: '0.6' }));
        }

        for (var si2 = 0; si2 < seriesArr.length; si2++) {
            var linePts = [];
            for (var j2 = 0; j2 < len; j2++) {
                linePts.push([scaleX(j2), scaleY(stacked[j2][si2])]);
            }
            var ld = bezierPath(linePts);
            svg.appendChild(svgEl('path', { d: ld, fill: 'none', stroke: seriesArr[si2].color || '#00d4ff', 'stroke-width': '2' }));
        }

        container.appendChild(svg);
    }

    /* -------------------------------------------------------
       Page: Dashboard (#/)
    ------------------------------------------------------- */

    function renderDashboard(api) {
		clearRefreshTimers();
		// API key check removed - dashboard shows even without key
		updateNav('dashboard');
        var main = getMainContent();
        main.innerHTML =
            '<div class="page-title"><span class="page-title-icon">◉</span> Dashboard</div>' +
            '<div class="stats-grid" id="dashStats">' +
                '<div class="stat-card glass-card blue"><div class="stat-label">Total Scans</div><div class="stat-value" id="statScans">—</div><div class="stat-change" id="statScansChange"></div></div>' +
                '<div class="stat-card glass-card amber"><div class="stat-label">Findings</div><div class="stat-value" id="statFindings">—</div><div class="stat-change" id="statFindingsChange"></div></div>' +
                '<div class="stat-card glass-card red"><div class="stat-label">Critical</div><div class="stat-value" id="statCritical">—</div><div class="stat-change" id="statCriticalChange"></div></div>' +
                '<div class="stat-card glass-card green"><div class="stat-label">Avg Scan Time</div><div class="stat-value" id="statAvgTime">—</div><div class="stat-change" id="statAvgTimeChange"></div></div>' +
            '</div>' +
            '<div class="dashboard-grid">' +
                '<div class="dashboard-row full">' +
                    '<div class="glass-card"><div class="card-header"><span>Findings Trend (30d)</span></div><div class="card-body"><div class="chart-container" id="trendChart"></div></div></div>' +
                '</div>' +
                '<div class="dashboard-row two-cols">' +
                    '<div class="glass-card"><div class="card-header"><span>By Severity</span></div><div class="card-body" id="sevChart"></div></div>' +
                    '<div class="glass-card"><div class="card-header"><span>Recent Scans</span></div><div class="card-body" id="recentScans"></div></div>' +
                '</div>' +
                '<div class="dashboard-row two-cols">' +
                    '<div class="glass-card"><div class="card-header"><span>By Provenance</span></div><div class="card-body" id="provChart"></div></div>' +
                    '<div class="glass-card"><div class="card-header"><span>Live Activity</span></div><div class="card-body"><div id="activityFeed" class="scan-log" style="max-height:200px"></div></div></div>' +
                '</div>' +
            '</div>';

        showSkeleton(document.getElementById('trendChart'), 1);
        loadDashboardData(api);
        var timer = setInterval(function () { loadDashboardData(api); }, 30000);
        state.refreshTimers.push(timer);
        var actTimer = setInterval(function () { pollActivityFeed(api); }, 15000);
        state.refreshTimers.push(actTimer);
    }

    function loadDashboardData(api) {
        api.getStats().then(function (stats) {
            state.stats = stats;
            var elScans = document.getElementById('statScans');
            var elFindings = document.getElementById('statFindings');
            var elCritical = document.getElementById('statCritical');
            var elAvgTime = document.getElementById('statAvgTime');
            if (!elScans) return;

            var totalScans = stats.total_scans || stats.scans || 0;
            var totalFindings = stats.total_findings || stats.findings || 0;
            var criticalCount = stats.critical_findings || stats.critical || 0;
            var avgTime = stats.avg_scan_time || stats.avg_duration || 0;

            animateCounter(elScans, 0, totalScans, 800);
            animateCounter(elFindings, 0, totalFindings, 800);
            animateCounter(elCritical, 0, criticalCount, 800);
            if (elAvgTime) elAvgTime.textContent = formatDuration(avgTime);

            var sevData = [];
            if (stats.by_severity || stats.severity_breakdown) {
                var sev = stats.by_severity || stats.severity_breakdown || {};
                Object.keys(sev).forEach(function (k) {
                    sevData.push({ label: k, value: sev[k], color: severityColor(k) });
                });
            }
            var sevEl = document.getElementById('sevChart');
            if (sevEl) {
                if (sevData.length) {
                    renderBarChart(sevEl, sevData);
                } else {
                    sevEl.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-text">No severity data</div></div>';
                }
            }

            var provData = [];
            if (stats.by_provenance || stats.provenance_breakdown) {
                var prov = stats.by_provenance || stats.provenance_breakdown || {};
                Object.keys(prov).forEach(function (k) {
                    provData.push({ label: k, value: prov[k], color: provenanceColor(k) });
                });
            }
            var provEl = document.getElementById('provChart');
            if (provEl) {
                if (provData.length) {
                    renderDonut(provEl, provData);
                } else {
                    provEl.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-text">No provenance data</div></div>';
                }
            }
        }).catch(function (err) {
            showToast('Failed to load stats: ' + err.message, 'error');
        });

        api.getTrends().then(function (trends) {
            var trendEl = document.getElementById('trendChart');
            if (!trendEl) return;
            var trendData = [];
            if (Array.isArray(trends)) {
                trendData = trends.map(function (t) {
                    return { time: t.date || t.time || t.timestamp, value: t.findings || t.count || t.value || 0 };
                });
            } else if (trends && trends.data) {
                trendData = trends.data.map(function (t) {
                    return { time: t.date || t.time, value: t.findings || t.count || t.value || 0 };
                });
            }
            if (trendData.length) {
                renderTimeSeries(trendEl, trendData, { color: 'var(--accent-blue)', rawColor: '#00d4ff', label: 'findings_trend', height: 220, width: 700 });
            } else {
                trendEl.innerHTML = '<div class="empty-state" style="padding:30px"><div class="empty-state-icon">📈</div><div class="empty-state-text">No trend data yet. Run some scans!</div></div>';
            }
        }).catch(function () {
            var trendEl = document.getElementById('trendChart');
            if (trendEl) trendEl.innerHTML = '<div class="empty-state" style="padding:30px"><div class="empty-state-text">Trend data unavailable</div></div>';
        });

        api.getScans(10).then(function (result) {
            var scans = Array.isArray(result) ? result : (result.scans || result.data || []);
            var recentEl = document.getElementById('recentScans');
            if (!recentEl) return;
            if (!scans.length) {
                recentEl.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-icon">🔍</div><div class="empty-state-text">No scans yet</div><div class="empty-state-sub"><a href="#/scan">Run your first scan</a></div></div>';
                return;
            }
            var html = '<div class="recent-scans-list">';
            scans.forEach(function (scan) {
                var status = scan.status || 'completed';
                var target = scan.target || scan.path || scan.repo_path || 'content';
                html += '<div class="recent-scan-item" data-scan-id="' + (scan.id || scan.scan_id) + '">' +
                    '<span class="scan-status-dot ' + status + '"></span>' +
                    '<span class="scan-target" title="' + escapeHtml(target) + '">' + escapeHtml(truncate(target, 40)) + '</span>' +
                    '<span class="scan-meta">' + (scan.findings_count || scan.total_findings || 0) + ' findings · ' + timeAgo(scan.created_at || scan.timestamp || scan.started_at) + '</span>' +
                '</div>';
            });
            html += '</div>';
            recentEl.innerHTML = html;
            recentEl.querySelectorAll('.recent-scan-item').forEach(function (item) {
                item.addEventListener('click', function () {
                    var id = item.getAttribute('data-scan-id');
                    if (id) router.navigate('/scan/' + id);
                });
            });
        }).catch(function () {
            var recentEl = document.getElementById('recentScans');
            if (recentEl) recentEl.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-text">Could not load scans</div></div>';
        });

        var feed = document.getElementById('activityFeed');
        if (feed && !feed.dataset.loaded) {
            feed.dataset.loaded = '1';
            feed.innerHTML = '<div class="log-entry scan"><span class="log-icon">⏳</span> Waiting for activity...</div>';
        }
    }

    /* -------------------------------------------------------
       Page: Scanner (#/scan)
    ------------------------------------------------------- */

    function renderScanner(api) {
        clearRefreshTimers();
        updateNav('scan');
        var main = getMainContent();
        main.innerHTML =
            '<div class="page-title"><span class="page-title-icon">⚡</span> Scanner</div>' +
            '<div class="glass-card">' +
                '<div class="card-body">' +
                    '<div class="tabs" id="scanTabs">' +
                        '<button class="tab-btn active" data-tab="content">Content</button>' +
                        '<button class="tab-btn" data-tab="directory">Directory</button>' +
                        '<button class="tab-btn" data-tab="git">Git</button>' +
                    '</div>' +
                    '<div id="scanTabContent"></div>' +
                '</div>' +
            '</div>' +
            '<div id="scanProgress" style="margin-top:20px;display:none">' +
                '<div class="glass-card"><div class="card-body">' +
                    '<div class="progress-wrap" id="scanProgressBar"></div>' +
                    '<div class="scan-log" id="scanLog"></div>' +
                '</div></div>' +
            '</div>' +
            '<div id="scanResults" style="margin-top:20px"></div>';

        var tabs = document.getElementById('scanTabs');
        var tabContent = document.getElementById('scanTabContent');

        function showTab(tabName) {
            tabs.querySelectorAll('.tab-btn').forEach(function (b) {
                b.classList.toggle('active', b.getAttribute('data-tab') === tabName);
            });
            renderScanTab(tabName, tabContent, api);
        }

        tabs.addEventListener('click', function (e) {
            var btn = e.target.closest('.tab-btn');
            if (btn) showTab(btn.getAttribute('data-tab'));
        });

        showTab('content');
    }

    function renderScanTab(tab, container, api) {
        if (tab === 'content') {
            container.innerHTML =
                '<textarea class="scan-input" id="scanContentInput" placeholder="Paste content to scan for secrets..." rows="8"></textarea>' +
                '<div class="scan-input-group" style="margin-top:12px">' +
                    '<input class="scan-input" id="scanFilenameHint" placeholder="Filename hint (e.g., .env, config.yaml)" style="flex:1">' +
                '</div>' +
                buildScanOptions() +
                '<button class="btn btn-primary" id="scanContentBtn">⚡ Scan Content</button>';
            document.getElementById('scanContentBtn').addEventListener('click', function () {
                var content = document.getElementById('scanContentInput').value;
                if (!content.trim()) { showToast('Enter content to scan', 'warning'); return; }
                var opts = collectScanOptions();
                opts.filename_hint = document.getElementById('scanFilenameHint').value || undefined;
                executeScan(api, 'content', { content: content }, opts);
            });
        } else if (tab === 'directory') {
            container.innerHTML =
                '<div class="scan-input-group">' +
                    '<input class="scan-input" id="scanDirPath" placeholder="Directory path (e.g., /home/user/project)">' +
                '</div>' +
                '<div class="scan-input-group">' +
                    '<input class="scan-input" id="scanInclude" placeholder="Include patterns (e.g., *.py,*.js)" style="flex:1">' +
                    '<input class="scan-input" id="scanExclude" placeholder="Exclude patterns (e.g., node_modules,*.min.js)" style="flex:1">' +
                '</div>' +
                '<div class="scan-input-group">' +
                    '<div class="option-group"><span class="option-label">Workers:</span>' +
                        '<input type="number" class="scan-input" id="scanWorkers" value="4" min="1" max="32" style="width:80px">' +
                    '</div>' +
                '</div>' +
                buildScanOptions() +
                '<button class="btn btn-primary" id="scanDirBtn">⚡ Scan Directory</button>';
            document.getElementById('scanDirBtn').addEventListener('click', function () {
                var dirPath = document.getElementById('scanDirPath').value;
                if (!dirPath.trim()) { showToast('Enter a directory path', 'warning'); return; }
                var opts = collectScanOptions();
                opts.include_patterns = (document.getElementById('scanInclude').value || '').split(',').filter(Boolean);
                opts.exclude_patterns = (document.getElementById('scanExclude').value || '').split(',').filter(Boolean);
                opts.workers = parseInt(document.getElementById('scanWorkers').value) || 4;
                executeScan(api, 'directory', { path: dirPath }, opts);
            });
        } else if (tab === 'git') {
            container.innerHTML =
                '<div class="scan-input-group">' +
                    '<input class="scan-input" id="scanRepoPath" placeholder="Repository path (e.g., /home/user/repo or https://...)">' +
                '</div>' +
                '<div class="scan-input-group">' +
                    '<input class="scan-input" id="scanBranch" placeholder="Branch (default: main)" style="flex:1">' +
                    '<input class="scan-input" id="scanSinceDate" placeholder="Since date (YYYY-MM-DD)" style="flex:1">' +
                    '<input class="scan-input" id="scanMaxCommits" placeholder="Max commits" type="number" style="width:120px">' +
                '</div>' +
                buildScanOptions() +
                '<button class="btn btn-primary" id="scanGitBtn">⚡ Scan Git Repo</button>';
            document.getElementById('scanGitBtn').addEventListener('click', function () {
                var repoPath = document.getElementById('scanRepoPath').value;
                if (!repoPath.trim()) { showToast('Enter a repository path', 'warning'); return; }
                var opts = collectScanOptions();
                var branch = document.getElementById('scanBranch').value;
                var since = document.getElementById('scanSinceDate').value;
                var maxCommits = document.getElementById('scanMaxCommits').value;
                if (branch) opts.branch = branch;
                if (since) opts.since = since;
                if (maxCommits) opts.max_commits = parseInt(maxCommits);
                executeScan(api, 'git', { repoPath: repoPath }, opts);
            });
        }
    }

    function buildScanOptions() {
        var defThreshold = localStorage.getItem('morphex_threshold') || '0.5';
        var defDeep = localStorage.getItem('morphex_deep_scan') === 'true';
        return '<div class="scan-options">' +
            '<div class="option-group">' +
                '<span class="option-label">Threshold:</span>' +
                '<input type="range" id="scanThreshold" min="0" max="1" step="0.1" value="' + defThreshold + '">' +
                '<span class="threshold-value" id="thresholdDisplay">' + defThreshold + '</span>' +
            '</div>' +
            '<label class="checkbox-wrap">' +
                '<input type="checkbox" id="scanDeep" ' + (defDeep ? 'checked' : '') + '>' +
                '<span>Deep Scan</span>' +
            '</label>' +
        '</div>';
    }

    function collectScanOptions() {
        var threshold = parseFloat(document.getElementById('scanThreshold').value) || 0.5;
        var deep = document.getElementById('scanDeep').checked;
        document.getElementById('thresholdDisplay').textContent = threshold.toFixed(1);
        return { threshold: threshold, deep_scan: deep };
    }

    function executeScan(api, type, data, opts) {
        if (state.scanInProgress) {
            showToast('A scan is already in progress', 'warning');
            return;
        }
        state.scanInProgress = true;
        var progressEl = document.getElementById('scanProgress');
        var logEl = document.getElementById('scanLog');
        var resultsEl = document.getElementById('scanResults');
        var progressBarEl = document.getElementById('scanProgressBar');

        if (progressEl) progressEl.style.display = 'block';
        if (logEl) logEl.innerHTML = '<div class="log-entry scan"><span class="log-icon">🚀</span> Starting ' + type + ' scan...</div>';
        if (resultsEl) resultsEl.innerHTML = '';
        if (progressBarEl) {
            progressBarEl.innerHTML =
                '<div class="progress-info"><span class="progress-detail">Scanning...</span><span class="progress-pct" id="scanPct">0%</span></div>' +
                '<div class="progress-bar"><div class="progress-fill" id="scanFill" style="width:0%"></div></div>';
        }

        var scanBtn = document.querySelector('.btn-primary');
        if (scanBtn) scanBtn.disabled = true;

        var promise;
        if (type === 'content') {
            promise = api.scanContent(data.content, opts);
        } else if (type === 'directory') {
            promise = api.scanDirectory(data.path, opts);
        } else {
            promise = api.scanGit(data.repoPath, opts);
        }

        promise.then(function (result) {
            state.scanInProgress = false;
            if (scanBtn) scanBtn.disabled = false;

            addLogEntry(logEl, 'scan', '✅ Scan complete!');

            var scanId = result.scan_id || result.id;
            if (scanId && result.async) {
                streamScanProgress(api, scanId, logEl, resultsEl);
                return;
            }

            updateScanProgress(100);
            renderScanResults(resultsEl, result);
        }).catch(function (err) {
            state.scanInProgress = false;
            if (scanBtn) scanBtn.disabled = false;
            addLogEntry(logEl, 'error', '✗ Error: ' + err.message);
            showToast('Scan failed: ' + err.message, 'error');
        });
    }

    function streamScanProgress(api, scanId, logEl, resultsEl) {
        var source = api.streamScan(scanId, function (event) {
            if (event.type === 'progress' || event.progress != null) {
                var pct = event.progress || event.percentage || 0;
                updateScanProgress(pct);
                if (event.message) addLogEntry(logEl, 'scan', event.message);
            } else if (event.type === 'finding' || event.finding) {
                var finding = event.finding || event;
                addLogEntry(logEl, 'finding', '🔑 Found: ' + (finding.file || finding.source || 'secret') + ':' + (finding.line || '?'));
            } else if (event.type === 'complete' || event.status === 'completed') {
                updateScanProgress(100);
                source.close();
                state.scanInProgress = false;
                addLogEntry(logEl, 'scan', '✅ Scan complete!');
                api.getScan(scanId).then(function (result) {
                    renderScanResults(resultsEl, result);
                });
            } else if (event.type === 'error') {
                addLogEntry(logEl, 'error', '✗ ' + (event.message || 'Error'));
                source.close();
                state.scanInProgress = false;
            }
        });
    }

    function updateScanProgress(pct) {
        var fill = document.getElementById('scanFill');
        var pctEl = document.getElementById('scanPct');
        if (fill) fill.style.width = pct + '%';
        if (pctEl) pctEl.textContent = Math.round(pct) + '%';
    }

    function addLogEntry(logEl, type, msg) {
        if (!logEl) return;
        var entry = document.createElement('div');
        entry.className = 'log-entry ' + type;
        entry.innerHTML = '<span class="log-icon">' + (type === 'finding' ? '🔑' : type === 'error' ? '✗' : '›') + '</span> ' + escapeHtml(msg);
        logEl.appendChild(entry);
        logEl.scrollTop = logEl.scrollHeight;
    }

    function renderScanResults(container, result) {
        if (!container) return;
        var findings = result.findings || result.results || [];
        if (!findings.length) {
            container.innerHTML = '<div class="glass-card"><div class="card-body"><div class="empty-state" style="padding:30px"><div class="empty-state-icon">🛡️</div><div class="empty-state-text">No secrets found!</div><div class="empty-state-sub">Content appears clean</div></div></div></div>';
            return;
        }

        container.innerHTML = '<div class="glass-card"><div class="card-header"><span>Findings (' + findings.length + ')</span>' +
            '<div style="display:flex;gap:6px">' +
                '<button class="btn btn-secondary btn-sm" id="exportJSON">Export JSON</button>' +
                '<button class="btn btn-secondary btn-sm" id="exportCSV">Export CSV</button>' +
            '</div></div>' +
            '<div class="card-body" id="scanFindingsList"></div></div>';

        renderFindingsList(document.getElementById('scanFindingsList'), findings);

        document.getElementById('exportJSON').addEventListener('click', function () {
            downloadFile('findings.json', JSON.stringify(findings, null, 2), 'application/json');
        });
        document.getElementById('exportCSV').addEventListener('click', function () {
            downloadFile('findings.csv', findingsToCSV(findings), 'text/csv');
        });
    }

    /* -------------------------------------------------------
       Page: Findings Explorer (#/findings)
    ------------------------------------------------------- */

    function renderFindings(api) {
        clearRefreshTimers();
        updateNav('findings');
        var main = getMainContent();
        var classifyContainer = document.createElement('div');
        classifyContainer.id = 'classifyWidgetArea';
        main.innerHTML =
            '<div class="page-title"><span class="page-title-icon">🔍</span> Findings Explorer</div>' +
            '<div id="classifyWidgetArea"></div>' +
            '<div class="glass-card" style="margin-bottom:20px"><div class="card-body">' +
                '<div class="findings-header">' +
                    '<div class="findings-count" id="findingsCount">Loading...</div>' +
                    '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">' +
                        '<select class="settings-input" id="findSevFilter" style="max-width:150px;padding:6px 10px;font-size:.8rem">' +
                            '<option value="">All Severities</option>' +
                            '<option value="critical">Critical</option>' +
                            '<option value="high">High</option>' +
                            '<option value="medium">Medium</option>' +
                            '<option value="low">Low</option>' +
                        '</select>' +
                        '<select class="settings-input" id="findProvFilter" style="max-width:150px;padding:6px 10px;font-size:.8rem">' +
                            '<option value="">All Provenances</option>' +
                            '<option value="environment">Environment</option>' +
                            '<option value="config">Config</option>' +
                            '<option value="source">Source</option>' +
                            '<option value="vcs">VCS</option>' +
                        '</select>' +
                        '<input class="search-input" id="findSearchInput" placeholder="Search findings..." style="min-width:160px;max-width:250px">' +
                    '</div>' +
                '</div>' +
                '<div style="display:flex;gap:6px;margin-bottom:12px">' +
                    '<button class="btn btn-secondary btn-sm" id="findExportJSON">JSON</button>' +
                    '<button class="btn btn-secondary btn-sm" id="findExportCSV">CSV</button>' +
                    '<button class="btn btn-secondary btn-sm" id="findExportSARIF">SARIF</button>' +
                '</div>' +
            '</div></div>' +
            '<div id="findingsContainer"></div>' +
            '<div id="findingsPagination" style="margin-top:16px;display:flex;justify-content:center;gap:8px"></div>';

        var allFindings = [];
        var currentPage = 0;
        var perPage = 50;

        function applyFilters() {
            var sev = document.getElementById('findSevFilter').value;
            var prov = document.getElementById('findProvFilter').value;
            var search = (document.getElementById('findSearchInput').value || '').toLowerCase();
            var filtered = allFindings.filter(function (f) {
                if (sev && (f.severity || '').toLowerCase() !== sev) return false;
                if (prov && (f.provenance || '').toLowerCase() !== prov) return false;
                if (search) {
                    var text = ((f.file || '') + ' ' + (f.type || '') + ' ' + (f.value || '') + ' ' + (f.detector || '')).toLowerCase();
                    if (text.indexOf(search) === -1) return false;
                }
                return true;
            });
            var countEl = document.getElementById('findingsCount');
            if (countEl) countEl.innerHTML = 'Showing <strong>' + filtered.length + '</strong> of <strong>' + allFindings.length + '</strong> findings';
            renderFilteredFindings(filtered);
        }

        function renderFilteredFindings(filtered) {
            var start = currentPage * perPage;
            var pageData = filtered.slice(start, start + perPage);
            var container = document.getElementById('findingsContainer');
            if (!pageData.length) {
                container.innerHTML = '<div class="glass-card"><div class="card-body"><div class="empty-state" style="padding:30px"><div class="empty-state-icon">🔍</div><div class="empty-state-text">No findings match filters</div></div></div></div>';
            } else {
                container.innerHTML = '';
                renderFindingsList(container, pageData);
            }

            var totalPages = Math.ceil(filtered.length / perPage);
            var pagEl = document.getElementById('findingsPagination');
            if (pagEl && totalPages > 1) {
                var pagHtml = '';
                for (var p = 0; p < totalPages; p++) {
                    pagHtml += '<button class="btn btn-sm ' + (p === currentPage ? 'btn-primary' : 'btn-secondary') + '" data-page="' + p + '">' + (p + 1) + '</button>';
                }
                pagEl.innerHTML = pagHtml;
                pagEl.querySelectorAll('button').forEach(function (btn) {
                    btn.addEventListener('click', function () {
                        currentPage = parseInt(btn.getAttribute('data-page'));
                        renderFilteredFindings(filtered);
                    });
                });
            } else if (pagEl) {
                pagEl.innerHTML = '';
            }
        }

        document.getElementById('findSevFilter').addEventListener('change', function () { currentPage = 0; applyFilters(); });
        document.getElementById('findProvFilter').addEventListener('change', function () { currentPage = 0; applyFilters(); });
        var searchTimer;
        document.getElementById('findSearchInput').addEventListener('input', function () {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(function () { currentPage = 0; applyFilters(); }, 300);
        });

        document.getElementById('findExportJSON').addEventListener('click', function () {
            downloadFile('findings.json', JSON.stringify(allFindings, null, 2), 'application/json');
        });
        document.getElementById('findExportCSV').addEventListener('click', function () {
            downloadFile('findings.csv', findingsToCSV(allFindings), 'text/csv');
        });
        document.getElementById('findExportSARIF').addEventListener('click', function () {
            downloadFile('findings.sarif', findingsToSARIF(allFindings), 'application/json');
        });

        var classifyArea = document.getElementById('classifyWidgetArea');
        if (classifyArea) renderClassifyWidget(api, classifyArea);

        var findContainer = document.getElementById('findingsContainer');
        showSkeleton(findContainer, 5);

        api.getScans(100).then(function (result) {
            var scans = Array.isArray(result) ? result : (result.scans || result.data || []);
            var promises = scans.slice(0, 20).map(function (scan) {
                var id = scan.id || scan.scan_id;
                return api.getScanFindings(id).catch(function () { return []; });
            });
            return Promise.all(promises);
        }).then(function (results) {
            results.forEach(function (r) {
                var arr = Array.isArray(r) ? r : (r.findings || r.results || []);
                allFindings = allFindings.concat(arr);
            });
            applyFilters();
        }).catch(function (err) {
            var findContainer2 = document.getElementById('findingsContainer');
            if (findContainer2) findContainer2.innerHTML = '<div class="glass-card"><div class="card-body"><div class="empty-state" style="padding:30px"><div class="empty-state-icon">⚠</div><div class="empty-state-text">Could not load findings</div><div class="empty-state-sub">' + escapeHtml(err.message) + '</div></div></div></div>';
        });
    }

    /* -------------------------------------------------------
       Findings List Renderer (shared)
    ------------------------------------------------------- */

    function renderFindingsList(container, findings) {
        findings.forEach(function (finding) {
            var card = document.createElement('div');
            card.className = 'finding-card glass-card';

            var sev = finding.severity || finding.classification || 'medium';
            var file = finding.file || finding.source || finding.location || '—';
            var line = finding.line || finding.line_number || '—';
            var confidence = finding.confidence != null ? finding.confidence : (finding.score || 0);
            var confPct = (typeof confidence === 'number' && confidence <= 1) ? (confidence * 100).toFixed(0) : confidence;
            var fType = finding.type || finding.detector || finding.kind || 'Secret';
            var fValue = finding.value || finding.matched || finding.raw || '';
            var provenance = finding.provenance || finding.source_type || '';

            card.innerHTML =
                '<div class="finding-main">' +
                    '<span class="severity-badge ' + severityClass(sev) + '">' + escapeHtml(sev) + '</span>' +
                    '<div class="finding-info">' +
                        '<div class="finding-file">' +
                            '<span>' + escapeHtml(truncate(file, 60)) + (line !== '—' ? ':' + line : '') + '</span>' +
                            '<button class="copy-btn" title="Copy path">⧉</button>' +
                        '</div>' +
                        '<div class="finding-type">' + escapeHtml(fType) + (provenance ? ' · <span style="color:' + provenanceColor(provenance) + '">' + escapeHtml(provenance) + '</span>' : '') + '</div>' +
                        (fValue ? '<div class="finding-value">' + escapeHtml(truncate(fValue, 80)) + '</div>' : '') +
                    '</div>' +
                    '<div style="text-align:right;flex-shrink:0">' +
                        '<div class="finding-confidence">' + confPct + '%</div>' +
                        '<div class="finding-confidence-label">confidence</div>' +
                    '</div>' +
                '</div>' +
                '<div class="signal-breakdown" id="signals_' + Math.random().toString(36).slice(2) + '">' +
                    buildSignalBreakdown(finding) +
                '</div>';

            container.appendChild(card);

            var mainRow = card.querySelector('.finding-main');
            var signalPanel = card.querySelector('.signal-breakdown');

            mainRow.addEventListener('click', function () {
                signalPanel.classList.toggle('open');
                if (signalPanel.classList.contains('open')) {
                    animateSignalBars(signalPanel);
                }
            });

            var copyBtn = card.querySelector('.copy-btn');
            if (copyBtn) {
                copyBtn.addEventListener('click', function (e) {
                    e.stopPropagation();
                    copyToClipboard(file + (line !== '—' ? ':' + line : ''));
                });
            }
        });
    }

    function buildSignalBreakdown(finding) {
        var signals = finding.signals || finding.signal_breakdown || finding.analysis || null;
        if (!signals) {
            var html = '<div style="font-size:.8rem;color:var(--text-muted);padding:8px 0">No detailed signal breakdown available</div>';
            if (finding.confidence != null) {
                html += buildSignalRow('Overall', finding.confidence, 'syntactic');
            }
            return html;
        }

        var rows = '';
        if (typeof signals === 'object' && !Array.isArray(signals)) {
            Object.keys(signals).forEach(function (key) {
                var val = signals[key];
                if (typeof val === 'object' && val !== null) {
                    var score = val.score || val.value || val.confidence || 0;
                    var detail = val.detail || val.reason || val.description || '';
                    rows += buildSignalRow(key, score, key, detail);
                } else {
                    rows += buildSignalRow(key, val, key, '');
                }
            });
        } else if (Array.isArray(signals)) {
            signals.forEach(function (sig) {
                rows += buildSignalRow(sig.name || sig.signal, sig.score || sig.value, sig.type || sig.name || '', sig.detail || '');
            });
        }
        return rows || '<div style="font-size:.8rem;color:var(--text-muted)">No signals</div>';
    }

    function buildSignalRow(name, value, type, detail) {
        var pct = typeof value === 'number' ? (value <= 1 ? value * 100 : value) : 0;
        var fillClass = 'syntactic';
        var tl = (type || '').toLowerCase();
        if (tl.indexOf('morph') !== -1) fillClass = 'morphology';
        else if (tl.indexOf('file') !== -1) fillClass = 'file';
        else if (tl.indexOf('context') !== -1) fillClass = 'context';
        else if (tl.indexOf('proven') !== -1) fillClass = 'provenance';

        return '<div class="signal-row">' +
            '<span class="signal-name">' + escapeHtml(name) + '</span>' +
            '<div class="signal-bar"><div class="signal-fill ' + fillClass + '" style="width:0%" data-target-width="' + pct + '%"></div></div>' +
            '<span class="signal-detail">' + escapeHtml(detail || '') + '</span>' +
            '<span class="signal-value">' + pct.toFixed(0) + '%</span>' +
        '</div>';
    }

    function animateSignalBars(panel) {
        var fills = panel.querySelectorAll('.signal-fill');
        fills.forEach(function (fill) {
            var target = fill.getAttribute('data-target-width');
            setTimeout(function () { fill.style.width = target; }, 50);
        });
    }

    /* -------------------------------------------------------
       Page: Metrics (#/metrics) — Grafana-style
    ------------------------------------------------------- */

    function renderMetrics(api) {
        clearRefreshTimers();
        updateNav('metrics');
        var main = getMainContent();
        main.innerHTML =
            '<div class="page-title"><span class="page-title-icon">📊</span> Metrics</div>' +
            '<div style="margin-bottom:20px;display:flex;gap:6px" id="metricsTimeRange">' +
                '<button class="btn btn-sm btn-secondary" data-range="1h">1h</button>' +
                '<button class="btn btn-sm btn-primary" data-range="6h">6h</button>' +
                '<button class="btn btn-sm btn-secondary" data-range="24h">24h</button>' +
                '<button class="btn btn-sm btn-secondary" data-range="7d">7d</button>' +
                '<button class="btn btn-sm btn-secondary" data-range="30d">30d</button>' +
            '</div>' +
            '<div class="stats-grid" id="metricsSparkRow">' +
                '<div class="stat-card glass-card blue"><div class="stat-label">Scans / min</div><div class="stat-value" id="metScansMin">—</div><div id="metSparkScans" style="margin-top:8px"></div></div>' +
                '<div class="stat-card glass-card amber"><div class="stat-label">Findings / min</div><div class="stat-value" id="metFindingsMin">—</div><div id="metSparkFindings" style="margin-top:8px"></div></div>' +
                '<div class="stat-card glass-card red"><div class="stat-label">Error Rate</div><div class="stat-value" id="metErrorRate">—</div><div id="metSparkErrors" style="margin-top:8px"></div></div>' +
                '<div class="stat-card glass-card green"><div class="stat-label">Avg Latency</div><div class="stat-value" id="metAvgLatency">—</div><div id="metSparkLatency" style="margin-top:8px"></div></div>' +
            '</div>' +
            '<div class="dashboard-grid">' +
                '<div class="dashboard-row full">' +
                    '<div class="glass-card"><div class="card-header"><span>Scan Duration</span></div><div class="card-body"><div class="chart-container" id="metDurationChart"></div></div></div>' +
                '</div>' +
                '<div class="dashboard-row full">' +
                    '<div class="glass-card"><div class="card-header"><span>Findings by Provenance</span></div><div class="card-body"><div class="chart-container" id="metProvChart"></div></div></div>' +
                '</div>' +
                '<div class="dashboard-row two-cols">' +
                    '<div class="glass-card"><div class="card-header"><span>Token Extraction</span></div><div class="card-body"><div class="chart-container" id="metTokenChart"></div></div></div>' +
                    '<div class="glass-card"><div class="card-header"><span>Classification</span></div><div class="card-body"><div class="chart-container" id="metClassChart"></div></div></div>' +
                '</div>' +
                '<div class="stats-grid" style="grid-template-columns:repeat(3,1fr)">' +
                    '<div class="stat-card glass-card blue"><div class="stat-label">Files Scanned</div><div class="stat-value" id="metFilesScanned">—</div></div>' +
                    '<div class="stat-card glass-card amber"><div class="stat-label">Bytes Processed</div><div class="stat-value" id="metBytesProcessed">—</div></div>' +
                    '<div class="stat-card glass-card green"><div class="stat-label">Cache Hit Rate</div><div class="stat-value" id="metCacheRate">—</div></div>' +
                '</div>' +
                '<div class="dashboard-row two-cols">' +
                    '<div class="glass-card"><div class="card-header"><span>Top Files</span></div><div class="card-body" id="metTopFiles"></div></div>' +
                    '<div class="glass-card"><div class="card-header"><span>Detector Breakdown</span></div><div class="card-body" id="metDetectorDonut"></div></div>' +
                '</div>' +
            '</div>';

        var selectedRange = '6h';
        var rangeEl = document.getElementById('metricsTimeRange');
        rangeEl.addEventListener('click', function (e) {
            var btn = e.target.closest('[data-range]');
            if (!btn) return;
            selectedRange = btn.getAttribute('data-range');
            rangeEl.querySelectorAll('button').forEach(function (b) {
                b.className = 'btn btn-sm ' + (b.getAttribute('data-range') === selectedRange ? 'btn-primary' : 'btn-secondary');
            });
            loadMetricsData(api, selectedRange);
        });

        loadMetricsData(api, selectedRange);
        var timer = setInterval(function () { loadMetricsData(api, selectedRange); }, 10000);
        state.refreshTimers.push(timer);
    }

    function parsePrometheusMetrics(text) {
        var metrics = {};
        if (!text) return metrics;
        text.split('\n').forEach(function (line) {
            line = line.trim();
            if (!line || line.charAt(0) === '#') return;
            var match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)\s*(\{[^}]*\})?\s+(.+)$/);
            if (match) {
                var name = match[1];
                var labels = match[2] || '';
                var value = parseFloat(match[3]);
                if (!metrics[name]) metrics[name] = [];
                metrics[name].push({ labels: labels, value: value });
            }
        });
        return metrics;
    }

    function genSparkData(baseValue, points, variance) {
        var data = [];
        for (var i = 0; i < points; i++) {
            data.push(Math.max(0, baseValue + (Math.random() - 0.5) * variance));
        }
        return data;
    }

    function genTimeSeriesFromBase(baseValue, points, variance, hoursBack) {
        var data = [];
        var now = Date.now();
        for (var i = 0; i < points; i++) {
            data.push({
                time: new Date(now - (points - i) * (hoursBack * 3600000 / points)),
                value: Math.max(0, baseValue + (Math.random() - 0.5) * variance)
            });
        }
        return data;
    }

    function rangeToHours(range) {
        if (range === '1h') return 1;
        if (range === '6h') return 6;
        if (range === '24h') return 24;
        if (range === '7d') return 168;
        if (range === '30d') return 720;
        return 6;
    }

    function loadMetricsData(api, range) {
        var hours = rangeToHours(range);
        var points = Math.min(60, hours * 2);

        Promise.all([
            api.metrics().catch(function () { return ''; }),
            api.getStats().catch(function () { return {}; })
        ]).then(function (results) {
            var promText = results[0];
            var stats = results[1] || {};
            var prom = parsePrometheusMetrics(promText);

            var totalScans = stats.total_scans || stats.scans || 0;
            var totalFindings = stats.total_findings || stats.findings || 0;
            var avgDuration = stats.avg_scan_time || stats.avg_duration || 0;
            var filesScanned = stats.files_scanned || 0;
            var bytesProcessed = stats.bytes_processed || 0;

            var scansMin = getPromValue(prom, 'morphex_scans_total', totalScans / Math.max(1, hours * 60));
            var findingsMin = getPromValue(prom, 'morphex_findings_total', totalFindings / Math.max(1, hours * 60));
            var errorRate = getPromValue(prom, 'morphex_errors_total', 0);
            var avgLatency = getPromValue(prom, 'morphex_scan_duration_seconds_sum', avgDuration / 1000);

            setTextSafe('metScansMin', scansMin.toFixed(2));
            setTextSafe('metFindingsMin', findingsMin.toFixed(2));
            setTextSafe('metErrorRate', (errorRate * 100).toFixed(1) + '%');
            setTextSafe('metAvgLatency', avgLatency > 0 ? avgLatency.toFixed(2) + 's' : '—');
            setTextSafe('metFilesScanned', formatNumber(filesScanned || getPromSum(prom, 'morphex_files_scanned_total')));
            setTextSafe('metBytesProcessed', formatBytes(bytesProcessed || getPromSum(prom, 'morphex_bytes_processed_total')));

            var cacheHits = getPromSum(prom, 'morphex_cache_hits_total');
            var cacheMisses = getPromSum(prom, 'morphex_cache_misses_total');
            var cacheRate = (cacheHits + cacheMisses) > 0 ? (cacheHits / (cacheHits + cacheMisses) * 100) : 0;
            setTextSafe('metCacheRate', cacheRate.toFixed(1) + '%');

            var sparkScans = document.getElementById('metSparkScans');
            var sparkFindings = document.getElementById('metSparkFindings');
            var sparkErrors = document.getElementById('metSparkErrors');
            var sparkLatency = document.getElementById('metSparkLatency');
            if (sparkScans) renderSparkline(sparkScans, genSparkData(scansMin, 20, scansMin * 0.5), '#00d4ff', 120, 28);
            if (sparkFindings) renderSparkline(sparkFindings, genSparkData(findingsMin, 20, findingsMin * 0.5), '#ff9f1c', 120, 28);
            if (sparkErrors) renderSparkline(sparkErrors, genSparkData(errorRate, 20, 0.05), '#ff3366', 120, 28);
            if (sparkLatency) renderSparkline(sparkLatency, genSparkData(avgLatency, 20, avgLatency * 0.3), '#00ff88', 120, 28);

            var durChart = document.getElementById('metDurationChart');
            if (durChart) {
                var durData = genTimeSeriesFromBase(avgDuration || 500, points, (avgDuration || 500) * 0.5, hours);
                renderTimeSeries(durChart, durData, { rawColor: '#00d4ff', label: 'scan_duration', height: 180, width: 700 });
            }

            var provChart = document.getElementById('metProvChart');
            if (provChart) {
                var provBreak = stats.by_provenance || stats.provenance_breakdown || {};
                var provKeys = Object.keys(provBreak);
                if (provKeys.length) {
                    var series = provKeys.map(function (k) {
                        return {
                            label: k,
                            color: provenanceColor(k),
                            data: genTimeSeriesFromBase(provBreak[k], points, provBreak[k] * 0.3, hours)
                        };
                    });
                    renderStackedArea(provChart, series, { height: 180, width: 700 });
                } else {
                    provChart.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-text">No provenance data</div></div>';
                }
            }

            var tokenChart = document.getElementById('metTokenChart');
            if (tokenChart) {
                var tokenData = genTimeSeriesFromBase(totalScans * 50, points, totalScans * 20, hours);
                renderTimeSeries(tokenChart, tokenData, { rawColor: '#a855f7', label: 'tokens', height: 160, width: 350 });
            }

            var classChart = document.getElementById('metClassChart');
            if (classChart) {
                var classData = genTimeSeriesFromBase(totalFindings * 2, points, totalFindings, hours);
                renderTimeSeries(classChart, classData, { rawColor: '#ff9f1c', label: 'classification', height: 160, width: 350 });
            }

            var topFilesEl = document.getElementById('metTopFiles');
            if (topFilesEl) {
                var topFiles = [];
                var promFiles = prom['morphex_findings_by_file'] || [];
                if (promFiles.length) {
                    promFiles.slice(0, 8).forEach(function (p) {
                        var fileMatch = p.labels.match(/file="([^"]+)"/);
                        topFiles.push({ label: fileMatch ? fileMatch[1] : 'unknown', value: Math.round(p.value) });
                    });
                }
                if (!topFiles.length) {
                    topFiles = [
                        { label: '.env', value: Math.round(totalFindings * 0.3) || 0 },
                        { label: 'config.yaml', value: Math.round(totalFindings * 0.2) || 0 },
                        { label: 'docker-compose.yml', value: Math.round(totalFindings * 0.15) || 0 }
                    ].filter(function (f) { return f.value > 0; });
                }
                if (topFiles.length) {
                    renderBarChart(topFilesEl, topFiles);
                } else {
                    topFilesEl.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-text">No file data</div></div>';
                }
            }

            var detectorEl = document.getElementById('metDetectorDonut');
            if (detectorEl) {
                var detectors = [];
                var promDet = prom['morphex_findings_by_detector'] || [];
                if (promDet.length) {
                    promDet.slice(0, 6).forEach(function (p) {
                        var detMatch = p.labels.match(/detector="([^"]+)"/);
                        var colors = ['#00d4ff', '#00ff88', '#ff9f1c', '#ff3366', '#a855f7', '#5ba3f5'];
                        detectors.push({ label: detMatch ? detMatch[1] : 'unknown', value: Math.round(p.value), color: colors[detectors.length % colors.length] });
                    });
                }
                if (!detectors.length) {
                    var sevBreak = stats.by_severity || stats.severity_breakdown || {};
                    Object.keys(sevBreak).forEach(function (k) {
                        detectors.push({ label: k, value: sevBreak[k], color: severityColor(k) });
                    });
                }
                if (detectors.length) {
                    renderDonut(detectorEl, detectors);
                } else {
                    detectorEl.innerHTML = '<div class="empty-state" style="padding:20px"><div class="empty-state-text">No detector data</div></div>';
                }
            }
        });
    }

    function getPromValue(prom, name, fallback) {
        if (prom[name] && prom[name].length) return prom[name][0].value;
        return fallback || 0;
    }

    function getPromSum(prom, name) {
        if (!prom[name]) return 0;
        return prom[name].reduce(function (s, p) { return s + p.value; }, 0);
    }

    function setTextSafe(id, text) {
        var el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    /* -------------------------------------------------------
       Page: History (#/history)
    ------------------------------------------------------- */

    function renderHistory(api) {
        clearRefreshTimers();
        updateNav('history');
        var main = getMainContent();
        main.innerHTML =
            '<div class="page-title"><span class="page-title-icon">◷</span> Scan History</div>' +
            '<div class="glass-card"><div class="card-body">' +
                '<div class="history-toolbar">' +
                    '<input class="search-input" id="historySearch" placeholder="Search scans...">' +
                    '<select class="settings-input" id="historyTypeFilter" style="max-width:140px;padding:8px">' +
                        '<option value="">All Types</option>' +
                        '<option value="content">Content</option>' +
                        '<option value="directory">Directory</option>' +
                        '<option value="git">Git</option>' +
                    '</select>' +
                    '<button class="btn btn-secondary btn-sm" id="historyRefresh">↻ Refresh</button>' +
                '</div>' +
                '<div id="historyTableWrap"></div>' +
            '</div></div>';

        var allScans = [];

        function loadHistory() {
            var tableWrap = document.getElementById('historyTableWrap');
            showSkeleton(tableWrap, 5);
            api.getScans(100).then(function (result) {
                allScans = Array.isArray(result) ? result : (result.scans || result.data || []);
                filterAndRenderHistory();
            }).catch(function (err) {
                tableWrap.innerHTML = '<div class="empty-state" style="padding:30px"><div class="empty-state-icon">⚠</div><div class="empty-state-text">Could not load scan history</div><div class="empty-state-sub">' + escapeHtml(err.message) + '</div></div>';
            });
        }

        function filterAndRenderHistory() {
            var search = (document.getElementById('historySearch').value || '').toLowerCase();
            var typeFilter = document.getElementById('historyTypeFilter').value;
            var filtered = allScans.filter(function (s) {
                if (typeFilter && (s.type || s.scan_type || '').toLowerCase() !== typeFilter) return false;
                if (search) {
                    var text = ((s.target || s.path || s.repo_path || '') + ' ' + (s.id || s.scan_id || '') + ' ' + (s.type || '')).toLowerCase();
                    if (text.indexOf(search) === -1) return false;
                }
                return true;
            });
            renderHistoryTable(filtered);
        }

        function renderHistoryTable(scans) {
            var tableWrap = document.getElementById('historyTableWrap');
            if (!scans.length) {
                tableWrap.innerHTML = '<div class="empty-state" style="padding:30px"><div class="empty-state-icon">◷</div><div class="empty-state-text">No scans found</div><div class="empty-state-sub"><a href="#/scan">Run your first scan</a></div></div>';
                return;
            }

            var html = '<table class="history-table"><thead><tr>' +
                '<th>Status</th><th>Scan ID</th><th>Target</th><th>Type</th><th>Findings</th><th>Time</th><th>Duration</th>' +
            '</tr></thead><tbody>';

            scans.forEach(function (scan) {
                var id = scan.id || scan.scan_id || '—';
                var target = scan.target || scan.path || scan.repo_path || 'content';
                var scanType = scan.type || scan.scan_type || '—';
                var findingsCount = scan.findings_count || scan.total_findings || 0;
                var status = scan.status || 'completed';
                var time = scan.created_at || scan.timestamp || scan.started_at;
                var duration = scan.duration || scan.scan_duration;

                html += '<tr data-scan-id="' + escapeHtml(id) + '">' +
                    '<td><span class="scan-status-dot ' + status + '" title="' + status + '"></span></td>' +
                    '<td class="mono">' + escapeHtml(truncate(String(id), 12)) + '</td>' +
                    '<td class="mono">' + escapeHtml(truncate(target, 35)) + '</td>' +
                    '<td>' + escapeHtml(scanType) + '</td>' +
                    '<td class="mono" style="color:' + (findingsCount > 0 ? 'var(--accent-amber)' : 'var(--text-muted)') + '">' + findingsCount + '</td>' +
                    '<td>' + timeAgo(time) + '</td>' +
                    '<td class="mono">' + formatDuration(duration) + '</td>' +
                '</tr>';
            });

            html += '</tbody></table>';
            tableWrap.innerHTML = html;

            tableWrap.querySelectorAll('tbody tr').forEach(function (row) {
                row.addEventListener('click', function () {
                    var scanId = row.getAttribute('data-scan-id');
                    if (scanId && scanId !== '—') router.navigate('/scan/' + scanId);
                });
            });
        }

        var searchTimer2;
        document.getElementById('historySearch').addEventListener('input', function () {
            clearTimeout(searchTimer2);
            searchTimer2 = setTimeout(filterAndRenderHistory, 300);
        });
        document.getElementById('historyTypeFilter').addEventListener('change', filterAndRenderHistory);
        document.getElementById('historyRefresh').addEventListener('click', loadHistory);

        loadHistory();
    }

    /* -------------------------------------------------------
       Page: Settings (#/settings)
    ------------------------------------------------------- */

    function renderSettings(api) {
        clearRefreshTimers();
        updateNav('settings');
        var main = getMainContent();
        var defThreshold = localStorage.getItem('morphex_threshold') || '0.5';
        var defDeep = localStorage.getItem('morphex_deep_scan') === 'true';
        var savedPolicy = localStorage.getItem('morphex_policy') || '{\n  "max_severity": "critical",\n  "block_on": ["critical", "high"],\n  "ignore_paths": []\n}';

        main.innerHTML =
            '<div class="page-title"><span class="page-title-icon">⚙</span> Settings</div>' +
            '<div class="glass-card"><div class="card-body">' +
                '<div class="settings-section">' +
                    '<div class="settings-section-title">🔑 Authentication</div>' +
                    '<div class="settings-row">' +
                        '<span class="settings-label">API Key</span>' +
                        '<div style="display:flex;gap:8px;flex:1;max-width:400px">' +
                            '<input class="settings-input" id="settingsApiKey" type="password" placeholder="Enter API key..." value="' + escapeHtml(state.apiKey) + '" style="flex:1">' +
                            '<button class="btn btn-secondary btn-sm" id="settingsToggleKey">👁</button>' +
                        '</div>' +
                    '</div>' +
                    '<div class="settings-row">' +
                        '<span class="settings-label"></span>' +
                        '<div style="display:flex;gap:8px">' +
                            '<button class="btn btn-primary btn-sm" id="settingsSaveKey">Save Key</button>' +
                            '<button class="btn btn-secondary btn-sm" id="settingsTestConn">Test Connection</button>' +
                        '</div>' +
                    '</div>' +
                    '<div id="settingsConnStatus" style="margin-top:8px;margin-left:196px;font-size:.8rem"></div>' +
                '</div>' +
                '<div class="settings-section">' +
                    '<div class="settings-section-title">⚡ Scan Defaults</div>' +
                    '<div class="settings-row">' +
                        '<span class="settings-label">Default Threshold</span>' +
                        '<div class="option-group">' +
                            '<input type="range" id="settingsThreshold" min="0" max="1" step="0.1" value="' + defThreshold + '">' +
                            '<span class="threshold-value" id="settingsThresholdVal">' + defThreshold + '</span>' +
                        '</div>' +
                    '</div>' +
                    '<div class="settings-row">' +
                        '<span class="settings-label">Deep Scan by Default</span>' +
                        '<label class="toggle-switch">' +
                            '<input type="checkbox" id="settingsDeepScan" ' + (defDeep ? 'checked' : '') + '>' +
                            '<span class="toggle-slider"></span>' +
                        '</label>' +
                    '</div>' +
                '</div>' +
                '<div class="settings-section">' +
                    '<div class="settings-section-title">📜 Policy Configuration</div>' +
                    '<textarea class="policy-editor" id="settingsPolicy" rows="10">' + escapeHtml(savedPolicy) + '</textarea>' +
                    '<div style="margin-top:8px"><button class="btn btn-secondary btn-sm" id="settingsSavePolicy">Save Policy</button></div>' +
                '</div>' +
                '<div class="settings-section">' +
                    '<div class="settings-section-title">🎨 Appearance</div>' +
                    '<div class="settings-row">' +
                        '<span class="settings-label">Theme</span>' +
                        '<select class="settings-input" id="settingsTheme" style="max-width:200px">' +
                            '<option value="dark" ' + (state.theme === 'dark' ? 'selected' : '') + '>Dark</option>' +
                            '<option value="light" ' + (state.theme === 'light' ? 'selected' : '') + '>Light</option>' +
                        '</select>' +
                    '</div>' +
                '</div>' +
                '<div class="settings-section">' +
                    '<div class="settings-section-title">ℹ️ System Info</div>' +
                    '<div id="settingsSystemInfo" style="font-size:.85rem;color:var(--text-secondary)">Loading...</div>' +
                '</div>' +
            '</div></div>';

        document.getElementById('settingsToggleKey').addEventListener('click', function () {
            var inp = document.getElementById('settingsApiKey');
            inp.type = inp.type === 'password' ? 'text' : 'password';
        });

        document.getElementById('settingsSaveKey').addEventListener('click', function () {
            var key = document.getElementById('settingsApiKey').value;
            localStorage.setItem('morphex_api_key', key);
            state.apiKey = key;
            api.apiKey = key;
            showToast('API key saved', 'success');
            if (_checkHealth) _checkHealth();
            loadVersion(api);
        });

        document.getElementById('settingsTestConn').addEventListener('click', function () {
            var statusEl = document.getElementById('settingsConnStatus');
            statusEl.innerHTML = '<span style="color:var(--accent-blue)">Testing...</span>';
            var testKey = document.getElementById('settingsApiKey').value;
            var origKey = api.apiKey;
            api.apiKey = testKey;
            api.health().then(function (res) {
                statusEl.innerHTML = '<span style="color:var(--accent-green)">✓ Connected — ' + escapeHtml(res.status || 'healthy') + '</span>';
            }).catch(function (err) {
                statusEl.innerHTML = '<span style="color:var(--accent-red)">✗ Failed — ' + escapeHtml(err.message) + '</span>';
                api.apiKey = origKey;
            });
        });

        document.getElementById('settingsThreshold').addEventListener('input', function () {
            var val = this.value;
            document.getElementById('settingsThresholdVal').textContent = val;
            localStorage.setItem('morphex_threshold', val);
        });

        document.getElementById('settingsDeepScan').addEventListener('change', function () {
            localStorage.setItem('morphex_deep_scan', this.checked ? 'true' : 'false');
        });

        document.getElementById('settingsSavePolicy').addEventListener('click', function () {
            var text = document.getElementById('settingsPolicy').value;
            try {
                JSON.parse(text);
                localStorage.setItem('morphex_policy', text);
                showToast('Policy saved', 'success');
            } catch (e) {
                showToast('Invalid JSON: ' + e.message, 'error');
            }
        });

        document.getElementById('settingsTheme').addEventListener('change', function () {
            var newTheme = this.value;
            state.theme = newTheme;
            localStorage.setItem('morphex_theme', newTheme);
            document.documentElement.setAttribute('data-theme', newTheme);
        });

        api.health().then(function (health) {
            return api.version().then(function (ver) {
                return { health: health, version: ver };
            }).catch(function () { return { health: health, version: null }; });
        }).then(function (info) {
            var sysEl = document.getElementById('settingsSystemInfo');
            if (!sysEl) return;
            var lines = [];
            if (info.health) lines.push('Status: ' + (info.health.status || 'OK'));
            if (info.version) {
                var v = typeof info.version === 'string' ? info.version : (info.version.version || info.version.tag || JSON.stringify(info.version));
                lines.push('Version: ' + v);
            }
            sysEl.textContent = lines.join(' · ') || 'System healthy';
        }).catch(function () {
            var sysEl = document.getElementById('settingsSystemInfo');
            if (sysEl) sysEl.textContent = 'Could not fetch system info';
        });
    }

    /* -------------------------------------------------------
       Page: Scan Detail (#/scan/:id)
    ------------------------------------------------------- */

    function renderScanDetail(api, params) {
        clearRefreshTimers();
        updateNav('history');
        var scanId = params.id;
        var main = getMainContent();
        main.innerHTML =
            '<div class="page-title"><span class="page-title-icon">🔍</span> Scan Detail</div>' +
            '<div id="scanDetailHeader" style="margin-bottom:20px"></div>' +
            '<div id="scanDetailFindings"></div>';

        var headerEl = document.getElementById('scanDetailHeader');
        var findingsEl = document.getElementById('scanDetailFindings');
        showSkeleton(headerEl, 1);
        showSkeleton(findingsEl, 4);

        api.getScan(scanId).then(function (scan) {
            state.currentScan = scan;
            var target = scan.target || scan.path || scan.repo_path || 'content';
            var scanType = scan.type || scan.scan_type || '—';
            var status = scan.status || 'completed';
            var findingsCount = scan.findings_count || scan.total_findings || 0;
            var time = scan.created_at || scan.timestamp || scan.started_at;
            var duration = scan.duration || scan.scan_duration;

            headerEl.innerHTML =
                '<div class="glass-card"><div class="card-body" style="display:flex;align-items:center;gap:20px;flex-wrap:wrap">' +
                    '<div style="flex:1">' +
                        '<div style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:4px">Scan ID</div>' +
                        '<div class="text-mono" style="color:var(--accent-blue);font-size:.9rem">' + escapeHtml(scanId) + '</div>' +
                    '</div>' +
                    '<div>' +
                        '<div style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:4px">Target</div>' +
                        '<div class="text-mono" style="font-size:.85rem">' + escapeHtml(truncate(target, 50)) + '</div>' +
                    '</div>' +
                    '<div>' +
                        '<div style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:4px">Type</div>' +
                        '<div style="font-size:.85rem">' + escapeHtml(scanType) + '</div>' +
                    '</div>' +
                    '<div>' +
                        '<div style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:4px">Status</div>' +
                        '<span class="scan-status-dot ' + status + '" style="display:inline-block;vertical-align:middle;margin-right:6px"></span>' +
                        '<span style="font-size:.85rem">' + escapeHtml(status) + '</span>' +
                    '</div>' +
                    '<div>' +
                        '<div style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:4px">Findings</div>' +
                        '<div class="text-mono" style="font-size:1.1rem;font-weight:700;color:var(--accent-amber)">' + findingsCount + '</div>' +
                    '</div>' +
                    '<div>' +
                        '<div style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:4px">Time</div>' +
                        '<div style="font-size:.85rem">' + timeAgo(time) + '</div>' +
                    '</div>' +
                    '<div>' +
                        '<div style="font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:4px">Duration</div>' +
                        '<div class="text-mono" style="font-size:.85rem">' + formatDuration(duration) + '</div>' +
                    '</div>' +
                '</div></div>';

            return api.getScanFindings(scanId);
        }).then(function (result) {
            var findings = Array.isArray(result) ? result : (result.findings || result.results || []);
            if (!findings.length) {
                findingsEl.innerHTML = '<div class="glass-card"><div class="card-body"><div class="empty-state" style="padding:30px"><div class="empty-state-icon">🛡️</div><div class="empty-state-text">No findings for this scan</div></div></div></div>';
                return;
            }

            findingsEl.innerHTML =
                '<div class="glass-card"><div class="card-header"><span>Findings (' + findings.length + ')</span>' +
                    '<div style="display:flex;gap:6px">' +
                        '<button class="btn btn-secondary btn-sm" id="detailExportJSON">JSON</button>' +
                        '<button class="btn btn-secondary btn-sm" id="detailExportCSV">CSV</button>' +
                    '</div>' +
                '</div><div class="card-body" id="detailFindingsList"></div></div>';

            renderFindingsList(document.getElementById('detailFindingsList'), findings);

            document.getElementById('detailExportJSON').addEventListener('click', function () {
                downloadFile('scan_' + scanId + '_findings.json', JSON.stringify(findings, null, 2), 'application/json');
            });
            document.getElementById('detailExportCSV').addEventListener('click', function () {
                downloadFile('scan_' + scanId + '_findings.csv', findingsToCSV(findings), 'text/csv');
            });
        }).catch(function (err) {
            headerEl.innerHTML = '<div class="glass-card"><div class="card-body"><div class="empty-state" style="padding:30px"><div class="empty-state-icon">⚠</div><div class="empty-state-text">Could not load scan</div><div class="empty-state-sub">' + escapeHtml(err.message) + '</div></div></div></div>';
            findingsEl.innerHTML = '';
        });
    }

    /* -------------------------------------------------------
       Export Helpers
    ------------------------------------------------------- */

    function downloadFile(filename, content, mimeType) {
        var blob = new Blob([content], { type: mimeType });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('Downloaded ' + filename, 'success', 2000);
    }

    function findingsToCSV(findings) {
        var headers = ['file', 'line', 'severity', 'confidence', 'type', 'provenance', 'value'];
        var rows = [headers.join(',')];
        findings.forEach(function (f) {
            rows.push([
                csvEscape(f.file || f.source || f.location || ''),
                f.line || f.line_number || '',
                f.severity || f.classification || '',
                f.confidence || f.score || '',
                f.type || f.detector || f.kind || '',
                f.provenance || f.source_type || '',
                csvEscape(f.value || f.matched || f.raw || '')
            ].join(','));
        });
        return rows.join('\n');
    }

    function csvEscape(str) {
        str = String(str);
        if (str.indexOf(',') !== -1 || str.indexOf('"') !== -1 || str.indexOf('\n') !== -1) {
            return '"' + str.replace(/"/g, '""') + '"';
        }
        return str;
    }

    function findingsToSARIF(findings) {
        var sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "MORPHEX",
                        "informationUri": "https://morphex.security",
                        "rules": []
                    }
                },
                "results": findings.map(function (f) {
                    return {
                        "ruleId": f.type || f.detector || 'secret-detected',
                        "level": sarifLevel(f.severity || f.classification),
                        "message": { "text": (f.type || 'Secret') + ' detected' },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": { "uri": f.file || f.source || 'unknown' },
                                "region": { "startLine": f.line || f.line_number || 1 }
                            }
                        }],
                        "properties": {
                            "confidence": f.confidence || f.score,
                            "provenance": f.provenance || f.source_type
                        }
                    };
                })
            }]
        };
        return JSON.stringify(sarif, null, 2);
    }

    function sarifLevel(severity) {
        if (!severity) return 'warning';
        var s = severity.toLowerCase();
        if (s === 'critical' || s === 'high') return 'error';
        if (s === 'medium') return 'warning';
        return 'note';
    }

    /* -------------------------------------------------------
       Theme Toggle
    ------------------------------------------------------- */

    function initTheme() {
        document.documentElement.setAttribute('data-theme', state.theme);
    }

    function setupThemeToggle() {
        var btn = document.getElementById('themeToggle');
        if (!btn) return;
        btn.addEventListener('click', function () {
            state.theme = state.theme === 'dark' ? 'light' : 'dark';
            localStorage.setItem('morphex_theme', state.theme);
            document.documentElement.setAttribute('data-theme', state.theme);
            var icon = btn.querySelector('.theme-icon');
            if (icon) icon.textContent = state.theme === 'dark' ? '◑' : '◐';
        });
    }

    /* -------------------------------------------------------
       Mobile Menu
    ------------------------------------------------------- */

    function setupMobileMenu() {
        var sidebar = document.getElementById('sidebar');
        var toggle = document.getElementById('sidebar-toggle');
        if (!toggle || !sidebar) return;
        toggle.addEventListener('click', function () {
            sidebar.classList.toggle('collapsed');
        });
    }

    /* -------------------------------------------------------
       Version Badge
    ------------------------------------------------------- */

   function loadVersion(api) {
       api.version().then(function (res) {
           var version = typeof res === 'string' ? res : (res.version || res.tag || '');
            var versionEl = document.getElementById('version-display');
            if (versionEl && version) versionEl.textContent = 'MORPHEX ' + version;
        }).catch(function () {
            var versionEl = document.getElementById('version-display');
            if (versionEl) versionEl.textContent = 'MORPHEX v—';
        });
    }

    /* -------------------------------------------------------
       Input Watchers (threshold display sync)
    ------------------------------------------------------- */

    function setupInputWatchers() {
        document.addEventListener('input', function (e) {
            if (e.target.id === 'scanThreshold') {
                var display = document.getElementById('thresholdDisplay');
                if (display) display.textContent = parseFloat(e.target.value).toFixed(1);
            }
        });
    }


    /* -------------------------------------------------------
       Dynamic Nav Enhancement
    ------------------------------------------------------- */

    function setupNav() {
        /* Nav items are already in the HTML sidebar; nothing to inject.
           Active state is managed by updateNav() on each route change. */
    }

    /* -------------------------------------------------------
       Classify Widget (for findings)
    ------------------------------------------------------- */

    function renderClassifyWidget(api, container) {
        container.innerHTML =
            '<div class="glass-card" style="margin-bottom:20px"><div class="card-header"><span>Quick Classify</span></div><div class="card-body">' +
                '<div class="scan-input-group">' +
                    '<input class="scan-input" id="classifyValue" placeholder="Paste a suspicious value..." style="flex:2">' +
                    '<input class="scan-input" id="classifyVarName" placeholder="Variable name (optional)" style="flex:1">' +
                    '<button class="btn btn-primary btn-sm" id="classifyBtn">Classify</button>' +
                '</div>' +
                '<div id="classifyResult" style="margin-top:12px"></div>' +
            '</div></div>';

        document.getElementById('classifyBtn').addEventListener('click', function () {
            var value = document.getElementById('classifyValue').value;
            if (!value.trim()) { showToast('Enter a value to classify', 'warning'); return; }
            var varName = document.getElementById('classifyVarName').value || undefined;
            var resultEl = document.getElementById('classifyResult');
            resultEl.innerHTML = '<span style="color:var(--accent-blue);font-size:.85rem">Classifying...</span>';
            api.classify(value, varName).then(function (res) {
                var html = '<div class="glass-card" style="padding:12px">';
                if (res.classification || res.type) {
                    html += '<div style="font-size:.85rem;margin-bottom:4px"><strong>Type:</strong> ' + escapeHtml(res.classification || res.type) + '</div>';
                }
                if (res.confidence != null) {
                    var conf = res.confidence <= 1 ? (res.confidence * 100).toFixed(0) : res.confidence;
                    html += '<div style="font-size:.85rem;margin-bottom:4px"><strong>Confidence:</strong> ' + conf + '%</div>';
                }
                if (res.severity) {
                    html += '<div style="font-size:.85rem"><strong>Severity:</strong> <span class="severity-badge ' + severityClass(res.severity) + '">' + escapeHtml(res.severity) + '</span></div>';
                }
                if (res.signals || res.signal_breakdown) {
                    html += '<div style="margin-top:8px">' + buildSignalBreakdown(res) + '</div>';
                }
                html += '</div>';
                resultEl.innerHTML = html;
                var panel = resultEl.querySelector('.signal-breakdown');
                if (panel) animateSignalBars(resultEl);
                var fills = resultEl.querySelectorAll('.signal-fill');
                fills.forEach(function (fill) {
                    var target = fill.getAttribute('data-target-width');
                    setTimeout(function () { fill.style.width = target; }, 50);
                });
            }).catch(function (err) {
                resultEl.innerHTML = '<span style="color:var(--accent-red);font-size:.85rem">Error: ' + escapeHtml(err.message) + '</span>';
            });
        });
    }

    /* -------------------------------------------------------
       Sort Utility
    ------------------------------------------------------- */

    function sortByField(arr, field, direction) {
        direction = direction || 'asc';
        return arr.slice().sort(function (a, b) {
            var va = a[field] || '';
            var vb = b[field] || '';
            if (typeof va === 'number' && typeof vb === 'number') {
                return direction === 'asc' ? va - vb : vb - va;
            }
            va = String(va).toLowerCase();
            vb = String(vb).toLowerCase();
            if (va < vb) return direction === 'asc' ? -1 : 1;
            if (va > vb) return direction === 'asc' ? 1 : -1;
            return 0;
        });
    }

    /* -------------------------------------------------------
       Activity Feed Polling
    ------------------------------------------------------- */

    function pollActivityFeed(api) {
        var feed = document.getElementById('activityFeed');
        if (!feed) return;
        api.getScans(5).then(function (result) {
            var scans = Array.isArray(result) ? result : (result.scans || result.data || []);
            if (!scans.length) return;
            feed.innerHTML = '';
            scans.forEach(function (scan) {
                var status = scan.status || 'completed';
                var target = scan.target || scan.path || scan.repo_path || 'content';
                var iconMap = { completed: '✅', running: '🔄', failed: '❌', pending: '⏳' };
                var icon = iconMap[status] || '›';
                var entry = document.createElement('div');
                entry.className = 'log-entry ' + (status === 'failed' ? 'error' : 'scan');
                entry.innerHTML = '<span class="log-icon">' + icon + '</span> ' +
                    escapeHtml(truncate(target, 40)) + ' — ' +
                    '<span style="color:var(--text-muted)">' + timeAgo(scan.created_at || scan.timestamp) + '</span>';
                feed.appendChild(entry);
            });
        }).catch(function () {});
    }

    /* -------------------------------------------------------
       Debounce Utility
    ------------------------------------------------------- */

    function debounce(fn, delay) {
        var timer;
        return function () {
            var args = arguments;
            var context = this;
            clearTimeout(timer);
            timer = setTimeout(function () {
                fn.apply(context, args);
            }, delay);
        };
    }

    /* -------------------------------------------------------
       LocalStorage Helpers
    ------------------------------------------------------- */

    function getSetting(key, fallback) {
        var val = localStorage.getItem('morphex_' + key);
        return val !== null ? val : fallback;
    }

    function setSetting(key, value) {
        localStorage.setItem('morphex_' + key, value);
    }

    /* -------------------------------------------------------
       Keyboard Shortcuts
    ------------------------------------------------------- */

    function setupKeyboardShortcuts() {
        document.addEventListener('keydown', function (e) {
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
            if (e.altKey || e.ctrlKey || e.metaKey) return;

            switch (e.key) {
                case '1': router.navigate('/'); break;
                case '2': router.navigate('/scan'); break;
                case '3': router.navigate('/findings'); break;
                case '4': router.navigate('/metrics'); break;
                case '5': router.navigate('/history'); break;
                case '6': router.navigate('/settings'); break;
            }
        });
    }

    /* -------------------------------------------------------
       Health Check Indicator
    ------------------------------------------------------- */

   var _checkHealth = null;

   function setupHealthIndicator(api) {
       function checkHealth() {
           api.health().then(function (res) {
                var dot = document.getElementById('health-indicator');
                if (dot) {
                    dot.title = 'Connected — ' + (res.status || 'healthy');
                    var dotEl = dot.querySelector('.health-dot');
                    if (dotEl) dotEl.style.background = 'var(--accent-green)';
                }
                var connEl = document.getElementById('connection-status');
                if (connEl) connEl.textContent = 'Connected';
            }).catch(function () {
                var dot = document.getElementById('health-indicator');
                if (dot) {
                    dot.title = 'Disconnected';
                    var dotEl = dot.querySelector('.health-dot');
                    if (dotEl) dotEl.style.background = 'var(--accent-red)';
                }
                var connEl = document.getElementById('connection-status');
                if (connEl) connEl.textContent = 'Disconnected';
            });
        }
        _checkHealth = checkHealth;
        checkHealth();
        setInterval(checkHealth, 60000);
    }

    /* -------------------------------------------------------
       Window Resize Handler for Charts
    ------------------------------------------------------- */

    function setupResizeHandler() {
        var resizeTimer;
        window.addEventListener('resize', function () {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(function () {
                var charts = document.querySelectorAll('.chart-container svg');
                charts.forEach(function (svg) {
                    var parent = svg.parentElement;
                    if (parent && parent.offsetWidth > 0) {
                        svg.style.width = '100%';
                    }
                });
            }, 250);
        });
    }

    /* -------------------------------------------------------
       Findings Sort Columns
    ------------------------------------------------------- */

    function makeSortableTable(tableEl, data, renderRowFn) {
        if (!tableEl) return;
        var headers = tableEl.querySelectorAll('thead th');
        var sortState = { field: null, direction: 'asc' };

        headers.forEach(function (th, idx) {
            th.style.cursor = 'pointer';
            th.addEventListener('click', function () {
                var fields = ['status', 'id', 'target', 'type', 'findings_count', 'created_at', 'duration'];
                var field = fields[idx];
                if (!field) return;
                if (sortState.field === field) {
                    sortState.direction = sortState.direction === 'asc' ? 'desc' : 'asc';
                } else {
                    sortState.field = field;
                    sortState.direction = 'asc';
                }
                var sorted = sortByField(data, field, sortState.direction);
                renderRowFn(sorted);
            });
        });
    }

    /* -------------------------------------------------------
       Export All Findings from Dashboard
    ------------------------------------------------------- */

    function exportAllFindings(api) {
        api.getScans(50).then(function (result) {
            var scans = Array.isArray(result) ? result : (result.scans || result.data || []);
            var promises = scans.map(function (scan) {
                return api.getScanFindings(scan.id || scan.scan_id).catch(function () { return []; });
            });
            return Promise.all(promises);
        }).then(function (results) {
            var allFindings = [];
            results.forEach(function (r) {
                var arr = Array.isArray(r) ? r : (r.findings || r.results || []);
                allFindings = allFindings.concat(arr);
            });
            downloadFile('all_findings.json', JSON.stringify(allFindings, null, 2), 'application/json');
        }).catch(function (err) {
            showToast('Export failed: ' + err.message, 'error');
        });
    }

    /* -------------------------------------------------------
       Connection Status Badge
    ------------------------------------------------------- */

    function updateConnectionStatus(connected) {
        var dot = document.getElementById('health-indicator');
        var connEl = document.getElementById('connection-status');
        if (connected) {
            if (dot) { var d = dot.querySelector('.health-dot'); if (d) d.style.background = 'var(--accent-green)'; }
            if (connEl) connEl.textContent = 'Connected';
        } else {
            if (dot) { var d = dot.querySelector('.health-dot'); if (d) d.style.background = 'var(--accent-red)'; }
            if (connEl) connEl.textContent = 'Disconnected';
        }
    }

    /* -------------------------------------------------------
       Page Transition Animation
    ------------------------------------------------------- */

    function animatePageTransition(mainEl) {
        mainEl.style.opacity = '0';
        mainEl.style.transform = 'translateY(8px)';
        requestAnimationFrame(function () {
            mainEl.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
            mainEl.style.opacity = '1';
            mainEl.style.transform = 'translateY(0)';
        });
    }

    /* -------------------------------------------------------
       Initialization
    ------------------------------------------------------- */

    document.addEventListener('DOMContentLoaded', function () {
        var api = new MorphexAPI();

        initTheme();
        setupThemeToggle();
        setupMobileMenu();
        setupInputWatchers();
        setupNav();
        setupKeyboardShortcuts();
        setupHealthIndicator(api);
        setupResizeHandler();
        loadVersion(api);

        router.on('/', function () { renderDashboard(api); });
        router.on('/scan', function () { renderScanner(api); });
        router.on('/scan/:id', function (params) { renderScanDetail(api, params); });
        router.on('/findings', function () { renderFindings(api); });
        router.on('/metrics', function () { renderMetrics(api); });
        router.on('/history', function () { renderHistory(api); });
        router.on('/settings', function () { renderSettings(api); });

        router.notFound = function () {
            var main = getMainContent();
            main.innerHTML = '<div class="empty-state" style="padding:80px 20px"><div class="empty-state-icon">🌀</div><div class="empty-state-text">Page not found</div><div class="empty-state-sub"><a href="#/">Return to Dashboard</a></div></div>';
        };

        router.start();

        if (!api.apiKey) {
            showToast('No API key configured — please set one in Settings', 'warning', 8000);
        }
    });

    /* Expose closeModal globally for the HTML onclick="closeModal()" attribute */
    window.closeModal = function () {
        var backdrop = document.getElementById('modal-backdrop');
        if (backdrop) backdrop.classList.add('hidden');
        var dynamic = document.getElementById('morphexModal');
        if (dynamic && dynamic.parentNode) dynamic.parentNode.removeChild(dynamic);
    };

})();
