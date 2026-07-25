/* グラフ調査ビュー — Maltego風のpivot調査用インタラクティブグラフ。
 * data.js (window.MALDB) から検体・C2・IOCの関連を実行時に索引化し、
 * 外部ライブラリなしの力学レイアウト + Canvas で描画する。
 * app.js から window.renderGraphView(container, query) で呼び出す。 */
(function () {
  "use strict";

  var DB = window.MALDB;
  if (!DB) return;

  var EXPAND_CAP = 40; // 1回の展開で追加する最大ノード数

  var TYPE_STYLE = {
    case:       { color: "#4fa8ff", r: 9,  jp: "検体ケース" },
    family:     { color: "#b58cff", r: 12, jp: "ファミリ" },
    campaign:   { color: "#6bdc8f", r: 10, jp: "キャンペーン" },
    intelcampaign: { color: "#55d6f5", r: 11, jp: "campaign相関候補" },
    collection: { color: "#8b9bb0", r: 8,  jp: "コレクション" },
    ip:         { color: "#ff6b7a", r: 9,  jp: "IPアドレス" },
    endpoint:   { color: "#ffa94d", r: 8,  jp: "接続先(host:port)" },
    domain:     { color: "#ffc76b", r: 9,  jp: "ドメイン" },
    url:        { color: "#ff8fd0", r: 8,  jp: "URL" },
    hash:       { color: "#7ee0c2", r: 8,  jp: "ファイルハッシュ" },
    misc:       { color: "#c9d4e0", r: 7,  jp: "その他IOC" }
  };

  /* ---------- エンティティ索引の構築 ---------- */

  var entities = null; // id -> {id,type,label,full}
  var adj = null;      // id -> (otherId -> edgeLabel)
  var byValue = null;  // 正規化値 -> id

  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function isIpv4(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s); }

  function addEntity(id, type, label, full) {
    if (!entities[id]) entities[id] = { id: id, type: type, label: label, full: full || label };
    return entities[id];
  }
  function addEdge(a, b, label) {
    if (a === b) return;
    if (!adj[a]) adj[a] = {};
    if (!adj[b]) adj[b] = {};
    if (!adj[a][b]) adj[a][b] = label || "";
    if (!adj[b][a]) adj[b][a] = label || "";
  }

  // host:port / host / URL / suffix付き(…/TCP)の値を正規化してノード群にする。
  // 返り値: この値を直接表すエンティティid
  function addNetworkValue(raw) {
    var v = String(raw).trim().replace(/\/(TCP|UDP|tcp|udp)$/, "");
    if (!v) return null;
    var m = v.match(/^(\w+):\/\/([^\/:?#]+)(?::(\d+))?([\/?#].*)?$/);
    if (m) { // URL
      var host = m[2].toLowerCase();
      var id = "url:" + v;
      addEntity(id, "url", shorten(v, 34), v);
      var hostId = addHost(host);
      if (hostId) addEdge(id, hostId, "ホスト");
      return id;
    }
    var hp = v.match(/^(.+):(\d{1,5})$/);
    if (hp && (isIpv4(hp[1]) || /^[a-z0-9.-]+$/i.test(hp[1]))) { // host:port
      var host2 = hp[1].toLowerCase();
      var eid = "endpoint:" + host2 + ":" + hp[2];
      addEntity(eid, "endpoint", host2 + ":" + hp[2], v);
      var hostId2 = addHost(host2);
      if (hostId2) addEdge(eid, hostId2, "ホスト");
      return eid;
    }
    return addHost(v.toLowerCase());
  }
  function addHost(host) {
    if (!host) return null;
    if (isIpv4(host)) { addEntity("ip:" + host, "ip", host); return "ip:" + host; }
    if (/^[a-z0-9._-]+\.[a-z0-9-]{2,}$/i.test(host)) {
      addEntity("domain:" + host, "domain", host);
      return "domain:" + host;
    }
    return null;
  }
  function shorten(s, n) { return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  var NETWORK_TYPES = { "接続先": 1, "ipv4": 1, "ipv6": 1, "ドメイン": 1, "domain": 1, "url": 1, "URL": 1 };
  var HASH_TYPES = { "sha256": 1, "SHA-256": 1, "sha1": 1, "md5": 1 };
  var SAMPLE_ROLES = { submitted_sample: 1, "提出検体": 1 };

  function buildIndex() {
    if (entities) return;
    entities = {}; adj = {}; byValue = {};

    DB.cases.forEach(function (c) {
      var cid = "case:" + c.sha256;
      addEntity(cid, "case", c.sha256.slice(0, 12) + "…", c.sha256);
      byValue[c.sha256] = cid;

      var famId = "family:" + c.family;
      addEntity(famId, "family", famLabel(c.family), c.family);
      addEdge(cid, famId, "ファミリ");

      if (c.campaign_type) {
        var cmpId = "campaign:" + c.campaign_type;
        addEntity(cmpId, "campaign", shorten(c.campaign_type, 30), c.campaign_type);
        addEdge(cid, cmpId, "キャンペーン");
        addEdge(famId, cmpId, "");
      }
      (c.collections || []).forEach(function (col) {
        var colId = "collection:" + col;
        addEntity(colId, "collection", shorten(col, 30), col);
        addEdge(cid, colId, "コレクション");
      });
      (c.c2 || []).forEach(function (v) {
        var id = addNetworkValue(v);
        if (id) { addEdge(cid, id, "C2/通信"); byValue[String(v).trim()] = id; }
      });
      c.iocs.forEach(function (e) {
        var val = String(e.value).trim();
        if (HASH_TYPES[e.type]) {
          if (SAMPLE_ROLES[e.role] || val.toLowerCase() === c.sha256) return; // 検体自身
          var low = val.toLowerCase();
          var hid;
          var other = DB.cases.some(function (x) { return x.sha256 === low; });
          if (other) hid = "case:" + low; // 既知ケースのハッシュはケースノードへ寄せる
          else {
            hid = "hash:" + low;
            addEntity(hid, "hash", low.slice(0, 12) + "…", low);
          }
          addEdge(cid, hid, e.role || "file_ioc");
          byValue[val] = byValue[val] || hid;
        } else if (NETWORK_TYPES[e.type]) {
          var nid = addNetworkValue(val);
          if (nid) { addEdge(cid, nid, e.role || "network"); byValue[val] = byValue[val] || nid; }
        } else {
          var mid = "misc:" + e.type + ":" + val;
          addEntity(mid, "misc", shorten(val, 26), e.type + ": " + val);
          addEdge(cid, mid, e.role || e.type);
          byValue[val] = byValue[val] || mid;
        }
      });
    });

    // campaign相関候補 (intelligence): 相関ケースと共有指標を接続する
    var intel = DB.intel || {};
    (intel.campaigns || []).forEach(function (g) {
      var gid = "intel:" + g.id;
      addEntity(gid, "intelcampaign", shorten(g.id.replace(/^correlated-/, ""), 30), g.id);
      byValue[g.id] = gid;
      g.members.forEach(function (sha) {
        if (entities["case:" + sha]) addEdge("case:" + sha, gid, "相関ケース");
      });
      (g.shared_indicators || []).forEach(function (s) {
        var nid = addNetworkValue(s.value);
        if (nid) addEdge(gid, nid, "共有指標 ×" + s.support);
      });
      (g.families || []).forEach(function (f) {
        if (entities["family:" + f]) addEdge(gid, "family:" + f, "");
      });
    });

    // コード完全一致リンク: 意味トークン列一致関数groupを共有するケースペア
    (intel.code_links || []).forEach(function (l) {
      var a = "case:" + l[0], b = "case:" + l[1];
      if (entities[a] && entities[b]) addEdge(a, b, "コード類似 " + l[2] + "関数");
    });
  }

  function famLabel(key) {
    var f = DB.families[key];
    return (f && (f.label || f.title)) || key;
  }

  function degree(id) {
    return adj[id] ? Object.keys(adj[id]).length : 0;
  }

  // 値・SHA-256前方一致・ラベルからエンティティを解決する
  function resolveEntity(q) {
    if (!q) return null;
    if (entities[q]) return q;
    var v = q.trim();
    if (byValue[v]) return byValue[v];
    if (/^[0-9a-f]{6,64}$/i.test(v)) {
      var low = v.toLowerCase();
      var hit = DB.cases.filter(function (c) { return c.sha256.indexOf(low) === 0; });
      if (hit.length === 1) return "case:" + hit[0].sha256;
    }
    var nid = null;
    Object.keys(entities).some(function (id) {
      if (entities[id].full === v || entities[id].label === v) { nid = id; return true; }
      return false;
    });
    return nid;
  }

  function searchEntities(q, limit) {
    var query = q.toLowerCase();
    var out = [];
    for (var id in entities) {
      var e = entities[id];
      if (e.full.toLowerCase().indexOf(query) >= 0 || e.label.toLowerCase().indexOf(query) >= 0) {
        out.push(e);
        if (out.length >= limit) break;
      }
    }
    // 次数が大きい(=pivot価値が高い)ものを上へ
    out.sort(function (a, b) { return degree(b.id) - degree(a.id); });
    return out;
  }

  /* ---------- グラフ状態と物理 ---------- */

  var nodes = {};    // id -> {id,x,y,vx,vy,pinned}
  var selected = null;
  var hovered = null;
  var alpha = 0;
  var physicsOn = true;
  var view = { scale: 1, ox: 0, oy: 0 };

  function shownEdges() {
    var out = [];
    for (var a in nodes) {
      var nb = adj[a] || {};
      for (var b in nb) {
        if (b > a && nodes[b]) out.push([a, b, nb[b]]);
      }
    }
    return out;
  }

  function addNode(id, nearId) {
    if (nodes[id]) return nodes[id];
    var base = nearId && nodes[nearId] ? nodes[nearId] : { x: 0, y: 0 };
    var ang = Math.random() * Math.PI * 2;
    var dist = 60 + Math.random() * 60;
    nodes[id] = {
      id: id,
      x: base.x + Math.cos(ang) * dist,
      y: base.y + Math.sin(ang) * dist,
      vx: 0, vy: 0, pinned: false
    };
    reheat();
    return nodes[id];
  }

  function removeNode(id) {
    delete nodes[id];
    if (selected === id) selected = null;
    reheat();
  }

  function expandNode(id, typeFilter) {
    var nb = adj[id] || {};
    var candidates = Object.keys(nb).filter(function (o) {
      if (nodes[o]) return false;
      if (typeFilter && entities[o].type !== typeFilter) return false;
      return true;
    });
    // 次数の小さいもの(特異な関連)を優先して追加
    candidates.sort(function (a, b) { return degree(a) - degree(b); });
    var added = candidates.slice(0, EXPAND_CAP);
    added.forEach(function (o) { addNode(o, id); });
    return { added: added.length, skipped: candidates.length - added.length };
  }

  function unexpandedCount(id) {
    var nb = adj[id] || {};
    var n = 0;
    for (var o in nb) if (!nodes[o]) n++;
    return n;
  }

  function reheat() { alpha = 1; saveSoon(); }

  // レイアウトを事前計算してから全体表示する(展開直後の暴れを抑える)
  function settleAndFit(steps) {
    alpha = 1;
    for (var i = 0; i < (steps || 150); i++) stepPhysics();
    alpha = 0.3;
    if (canvas) fitView();
    saveSoon();
  }

  function stepPhysics() {
    if (!physicsOn || alpha < 0.005) return;
    var ids = Object.keys(nodes);
    var n = ids.length;
    if (!n) return;
    var k = 90; // ばね自然長
    var i, j;
    // 斥力
    for (i = 0; i < n; i++) {
      var a = nodes[ids[i]];
      for (j = i + 1; j < n; j++) {
        var b = nodes[ids[j]];
        var dx = a.x - b.x, dy = a.y - b.y;
        var d2 = dx * dx + dy * dy;
        if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
        if (d2 > 250000) continue;
        var f = (k * k * 0.35) / d2;
        var fx = dx * f, fy = dy * f;
        a.vx += fx; a.vy += fy;
        b.vx -= fx; b.vy -= fy;
      }
    }
    // 引力(ばね)
    shownEdges().forEach(function (e) {
      var a = nodes[e[0]], b = nodes[e[1]];
      var dx = b.x - a.x, dy = b.y - a.y;
      var d = Math.sqrt(dx * dx + dy * dy) || 1;
      var f = (d - k) * 0.02;
      var fx = dx / d * f, fy = dy / d * f;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    });
    // 中心重力 + 積分
    ids.forEach(function (id) {
      var p = nodes[id];
      p.vx -= p.x * 0.002;
      p.vy -= p.y * 0.002;
      if (!p.pinned) {
        p.x += p.vx * alpha;
        p.y += p.vy * alpha;
      }
      p.vx *= 0.6; p.vy *= 0.6;
    });
    alpha *= 0.985;
  }

  /* ---------- 永続化 ---------- */

  var SAVE_KEY = "maldb-graph-v1";
  var saveTimer = null;
  function saveSoon() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(saveNow, 500);
  }
  function saveNow() {
    try {
      var out = Object.keys(nodes).map(function (id) {
        var p = nodes[id];
        return [id, Math.round(p.x), Math.round(p.y), p.pinned ? 1 : 0];
      });
      localStorage.setItem(SAVE_KEY, JSON.stringify(out));
    } catch (e) { /* localStorage不可でも動作継続 */ }
  }
  function restore() {
    try {
      var raw = localStorage.getItem(SAVE_KEY);
      if (!raw) return false;
      var arr = JSON.parse(raw);
      var ok = false;
      arr.forEach(function (r) {
        if (entities[r[0]]) {
          nodes[r[0]] = { id: r[0], x: r[1], y: r[2], vx: 0, vy: 0, pinned: !!r[3] };
          ok = true;
        }
      });
      return ok;
    } catch (e) { return false; }
  }

  /* ---------- 描画 ---------- */

  var canvas, ctx, wrap, sidebar, menuEl, tipEl;

  function worldToScreen(x, y) { return [x * view.scale + view.ox, y * view.scale + view.oy]; }
  function screenToWorld(x, y) { return [(x - view.ox) / view.scale, (y - view.oy) / view.scale]; }

  function draw() {
    if (!canvas || !canvas.isConnected) return;
    var w = canvas.clientWidth, h = canvas.clientHeight;
    var dpr = window.devicePixelRatio || 1;
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr; canvas.height = h * dpr;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    var neighborsOfSel = selected && adj[selected] ? adj[selected] : {};

    // 辺
    shownEdges().forEach(function (e) {
      var a = nodes[e[0]], b = nodes[e[1]];
      var p1 = worldToScreen(a.x, a.y), p2 = worldToScreen(b.x, b.y);
      var hot = selected && (e[0] === selected || e[1] === selected);
      ctx.strokeStyle = hot ? "rgba(79,168,255,0.85)" : "rgba(120,140,170,0.35)";
      ctx.lineWidth = hot ? 1.6 : 1;
      ctx.beginPath();
      ctx.moveTo(p1[0], p1[1]);
      ctx.lineTo(p2[0], p2[1]);
      ctx.stroke();
      if (hot && e[2] && view.scale > 0.55) {
        ctx.fillStyle = "rgba(139,155,176,0.9)";
        ctx.font = "10px sans-serif";
        ctx.fillText(e[2], (p1[0] + p2[0]) / 2 + 4, (p1[1] + p2[1]) / 2 - 4);
      }
    });

    // ノード
    for (var id in nodes) {
      var p = nodes[id];
      var e = entities[id];
      var st = TYPE_STYLE[e.type] || TYPE_STYLE.misc;
      var s = worldToScreen(p.x, p.y);
      var r = st.r * Math.max(0.7, Math.min(1.4, view.scale));
      var isSel = id === selected;
      var isHover = id === hovered;
      var isNb = neighborsOfSel[id] !== undefined;

      ctx.beginPath();
      ctx.arc(s[0], s[1], r, 0, Math.PI * 2);
      ctx.fillStyle = st.color;
      ctx.globalAlpha = selected && !isSel && !isNb ? 0.45 : 1;
      ctx.fill();
      ctx.globalAlpha = 1;
      if (isSel || isHover) {
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2;
        ctx.stroke();
      }
      if (p.pinned) {
        ctx.beginPath();
        ctx.arc(s[0], s[1], r + 3, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(255,255,255,0.5)";
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      // 未展開ノード数バッジ
      var un = unexpandedCount(id);
      if (un > 0 && view.scale > 0.4) {
        ctx.fillStyle = "#0d1117";
        ctx.beginPath();
        ctx.arc(s[0] + r * 0.9, s[1] - r * 0.9, 7, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "#7ee0c2";
        ctx.font = "bold 9px sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(un > 99 ? "99+" : String(un), s[0] + r * 0.9, s[1] - r * 0.9 + 3);
        ctx.textAlign = "start";
      }
      if (view.scale > 0.35 || isSel || isHover || isNb) {
        ctx.fillStyle = isSel || isHover || isNb || !selected ? "#dbe4ef" : "rgba(219,228,239,0.5)";
        ctx.font = (isSel ? "bold " : "") + "11px sans-serif";
        ctx.fillText(e.label, s[0] + r + 5, s[1] + 4);
      }
    }
  }

  function loop() {
    if (!canvas || !canvas.isConnected) return; // 画面遷移でループ終了
    stepPhysics();
    draw();
    requestAnimationFrame(loop);
  }

  function fitView() {
    var ids = Object.keys(nodes);
    if (!ids.length) return;
    var minX = 1e9, minY = 1e9, maxX = -1e9, maxY = -1e9;
    ids.forEach(function (id) {
      var p = nodes[id];
      minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
      minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
    });
    var w = canvas.clientWidth, h = canvas.clientHeight;
    var gw = Math.max(maxX - minX, 50), gh = Math.max(maxY - minY, 50);
    view.scale = Math.min(2, Math.min((w - 120) / gw, (h - 120) / gh));
    view.ox = w / 2 - (minX + maxX) / 2 * view.scale;
    view.oy = h / 2 - (minY + maxY) / 2 * view.scale;
  }

  function nodeAt(sx, sy) {
    var best = null, bestD = 1e9;
    for (var id in nodes) {
      var p = nodes[id];
      var s = worldToScreen(p.x, p.y);
      var st = TYPE_STYLE[entities[id].type] || TYPE_STYLE.misc;
      var r = Math.max(10, st.r * view.scale) + 4;
      var dx = sx - s[0], dy = sy - s[1];
      var d = dx * dx + dy * dy;
      if (d < r * r && d < bestD) { best = id; bestD = d; }
    }
    return best;
  }

  /* ---------- サイドバー / メニュー ---------- */

  function typeCounts(id) {
    var nb = adj[id] || {};
    var counts = {};
    for (var o in nb) {
      var t = entities[o].type;
      if (!counts[t]) counts[t] = { total: 0, shown: 0 };
      counts[t].total++;
      if (nodes[o]) counts[t].shown++;
    }
    return counts;
  }

  function entityPageHash(id) {
    var e = entities[id];
    if (e.type === "case") return "#/case/" + e.full;
    if (e.type === "family") return "#/family/" + e.full;
    if (e.type === "intelcampaign") return "#/intel/" + encodeURIComponent(e.full);
    if (e.type === "campaign") return "#/cases?campaign=" + encodeURIComponent(e.full);
    if (e.type === "collection") return "#/cases?collection=" + encodeURIComponent(e.full);
    return "#/iocs?q=" + encodeURIComponent(e.full.replace(/^[a-z]+: /, ""));
  }

  function renderSidebar() {
    if (!sidebar) return;
    if (!selected || !nodes[selected]) {
      sidebar.innerHTML =
        '<div class="gs-hint"><h3>グラフ調査</h3>' +
        "<p>上の検索からノードを追加し、ノードを<strong>ダブルクリック</strong>または右クリックで関連を展開してpivotします。</p>" +
        "<ul>" +
        "<li>ドラッグ: ノード移動(位置固定)</li>" +
        "<li>背景ドラッグ: 全体移動 / ホイール: 拡大縮小</li>" +
        "<li>右クリック: 種別ごとの展開・削除など</li>" +
        "<li>緑のバッジ: 未展開の関連ノード数</li>" +
        "</ul>" +
        '<div class="gs-legend">' + Object.keys(TYPE_STYLE).map(function (t) {
          return '<span><i style="background:' + TYPE_STYLE[t].color + '"></i>' + TYPE_STYLE[t].jp + "</span>";
        }).join("") + "</div></div>";
      return;
    }
    var e = entities[selected];
    var st = TYPE_STYLE[e.type] || TYPE_STYLE.misc;
    var counts = typeCounts(selected);
    var html = '<div class="gs-sel">' +
      '<div class="gs-type" style="color:' + st.color + '">' + esc(st.jp) + "</div>" +
      '<div class="gs-name mono">' + esc(e.full) + "</div>" +
      '<div class="gs-actions">' +
      '<button class="btn small" data-act="copy">値をコピー</button>' +
      '<a class="btn small" href="' + entityPageHash(selected) + '">ページを開く</a>' +
      '<button class="btn small" data-act="remove">ノード削除</button>' +
      "</div>";

    if (e.type === "case") {
      var c = null;
      DB.cases.some(function (x) { if (x.sha256 === e.full) { c = x; return true; } return false; });
      if (c) {
        html += '<dl class="gs-kv">' +
          "<dt>ファミリ</dt><dd>" + esc(famLabel(c.family)) + "</dd>" +
          (c.campaign_type ? "<dt>キャンペーン</dt><dd class='mono small'>" + esc(c.campaign_type) + "</dd>" : "") +
          (c.file_name ? "<dt>ファイル名</dt><dd class='mono small'>" + esc(c.file_name) + "</dd>" : "") +
          (c.first_seen ? "<dt>初観測</dt><dd class='mono small'>" + esc(c.first_seen) + "</dd>" : "") +
          "</dl>";
      }
    }

    html += "<h4>関連ノードの展開</h4>";
    var keys = Object.keys(counts);
    if (!keys.length) {
      html += '<p class="muted small">関連ノードがありません。</p>';
    } else {
      keys.sort(function (a, b) { return counts[b].total - counts[a].total; });
      html += keys.map(function (t) {
        var cc = counts[t];
        var stt = TYPE_STYLE[t] || TYPE_STYLE.misc;
        var done = cc.shown >= cc.total;
        return '<div class="gs-exp"><i style="background:' + stt.color + '"></i>' +
          '<span>' + esc(stt.jp) + ' <span class="muted">' + cc.shown + "/" + cc.total + "</span></span>" +
          (done ? '<span class="muted small">展開済み</span>'
                : '<button class="btn small" data-expand="' + t + '">展開</button>') +
          "</div>";
      }).join("");
      html += '<button class="btn small" style="margin-top:6px" data-act="expand-all">すべて展開</button>';
    }
    html += "</div>";
    sidebar.innerHTML = html;

    sidebar.querySelectorAll("[data-expand]").forEach(function (b) {
      b.addEventListener("click", function () {
        var r = expandNode(selected, b.getAttribute("data-expand"));
        notifyExpand(r);
        renderSidebar();
      });
    });
    var act = function (name, fn) {
      var b = sidebar.querySelector('[data-act="' + name + '"]');
      if (b) b.addEventListener("click", fn);
    };
    act("copy", function () { window.__copy(e.full); });
    act("remove", function () { removeNode(selected); renderSidebar(); });
    act("expand-all", function () {
      var r = expandNode(selected, null);
      notifyExpand(r);
      renderSidebar();
    });
  }

  function notifyExpand(r) {
    if (r.skipped > 0) toast(r.added + "件追加(" + r.skipped + "件は上限で省略。種別を絞って展開してください)");
    else if (r.added) toast(r.added + "件追加");
    else toast("追加できる関連ノードはありません");
    if (r.added) settleAndFit(120);
  }

  function toast(msg) {
    if (window.__toast) window.__toast(msg);
  }

  function hideMenu() { if (menuEl) { menuEl.remove(); menuEl = null; } }

  function showMenu(x, y, id) {
    hideMenu();
    var e = entities[id];
    var counts = typeCounts(id);
    var items = [];
    Object.keys(counts).sort(function (a, b) { return counts[b].total - counts[a].total; })
      .forEach(function (t) {
        var cc = counts[t];
        if (cc.shown < cc.total) {
          var stt = TYPE_STYLE[t] || TYPE_STYLE.misc;
          items.push({ label: stt.jp + " を展開 (" + (cc.total - cc.shown) + ")", fn: function () {
            notifyExpand(expandNode(id, t));
          } });
        }
      });
    items.push({ label: "すべて展開", fn: function () { notifyExpand(expandNode(id, null)); } });
    items.push({ label: "ページを開く", fn: function () { location.hash = entityPageHash(id); } });
    if (nodes[id] && nodes[id].pinned) {
      items.push({ label: "固定解除", fn: function () { nodes[id].pinned = false; reheat(); } });
    }
    items.push({ label: "このノードを削除", fn: function () { removeNode(id); renderSidebar(); } });
    items.push({ label: "このノード以外を削除", fn: function () {
      Object.keys(nodes).forEach(function (o) { if (o !== id) delete nodes[o]; });
      selected = id; reheat(); renderSidebar();
    } });

    menuEl = document.createElement("div");
    menuEl.className = "gs-menu";
    menuEl.innerHTML = '<div class="gs-menu-title mono">' + esc(e.label) + "</div>" +
      items.map(function (it, i) { return '<button data-i="' + i + '">' + esc(it.label) + "</button>"; }).join("");
    document.body.appendChild(menuEl);
    var mw = 240;
    menuEl.style.left = Math.min(x, window.innerWidth - mw - 10) + "px";
    menuEl.style.top = Math.min(y, window.innerHeight - menuEl.offsetHeight - 10) + "px";
    menuEl.querySelectorAll("button[data-i]").forEach(function (b) {
      b.addEventListener("click", function () {
        items[+b.getAttribute("data-i")].fn();
        hideMenu();
        renderSidebar();
      });
    });
  }

  /* ---------- ビュー本体 ---------- */

  window.renderGraphView = function (container, query) {
    buildIndex();
    hideMenu();

    container.innerHTML =
      '<div class="graph-toolbar">' +
      '<div class="gs-search"><input id="g-search" type="search" placeholder="ノードを追加: SHA-256 / IP / ドメイン / ファミリ / キャンペーン…" autocomplete="off">' +
      '<div id="g-search-results" class="gs-results" hidden></div></div>' +
      '<button class="btn small" id="g-fit">全体表示</button>' +
      '<button class="btn small" id="g-relayout">再レイアウト</button>' +
      '<button class="btn small" id="g-physics">物理: ON</button>' +
      '<button class="btn small" id="g-png">PNG保存</button>' +
      '<button class="btn small" id="g-clear">クリア</button>' +
      '<span class="count" id="g-count"></span>' +
      "</div>" +
      '<div class="graph-wrap"><canvas id="g-canvas"></canvas><div id="g-sidebar" class="graph-sidebar"></div>' +
      '<div id="g-tip" class="gs-tip" hidden></div></div>';

    wrap = container.querySelector(".graph-wrap");
    canvas = document.getElementById("g-canvas");
    ctx = canvas.getContext("2d");
    sidebar = document.getElementById("g-sidebar");
    tipEl = document.getElementById("g-tip");

    // 初期ノード: root指定があれば追加、なければ前回の保存内容を復元
    if (query.root) {
      var rid = resolveEntity(query.root);
      if (rid) {
        if (!nodes[rid]) {
          addNode(rid);
          expandNode(rid, null);
        }
        selected = rid;
      } else {
        toast("指定されたノードが見つかりません: " + query.root);
      }
    } else if (!Object.keys(nodes).length) {
      restore();
    }

    updateCount();
    renderSidebar();
    requestAnimationFrame(function () {
      settleAndFit(250);
      loop();
    });

    /* --- ツールバー --- */
    document.getElementById("g-fit").addEventListener("click", fitView);
    document.getElementById("g-relayout").addEventListener("click", function () {
      Object.keys(nodes).forEach(function (id) { nodes[id].pinned = false; });
      reheat();
    });
    var pbtn = document.getElementById("g-physics");
    pbtn.textContent = "物理: " + (physicsOn ? "ON" : "OFF");
    pbtn.addEventListener("click", function () {
      physicsOn = !physicsOn;
      pbtn.textContent = "物理: " + (physicsOn ? "ON" : "OFF");
      if (physicsOn) reheat();
    });
    document.getElementById("g-png").addEventListener("click", function () {
      var a = document.createElement("a");
      a.download = "malware-graph.png";
      a.href = canvas.toDataURL("image/png");
      a.click();
    });
    document.getElementById("g-clear").addEventListener("click", function () {
      nodes = {}; selected = null;
      saveNow(); updateCount(); renderSidebar();
    });

    /* --- 検索 --- */
    var sIn = document.getElementById("g-search");
    var sRes = document.getElementById("g-search-results");
    var sTimer = null;
    sIn.addEventListener("input", function () {
      clearTimeout(sTimer);
      sTimer = setTimeout(function () {
        var q = sIn.value.trim();
        if (q.length < 2) { sRes.hidden = true; return; }
        var found = searchEntities(q, 60).slice(0, 12);
        if (!found.length) { sRes.innerHTML = '<div class="muted small" style="padding:8px">一致なし</div>'; sRes.hidden = false; return; }
        sRes.innerHTML = found.map(function (e) {
          var st = TYPE_STYLE[e.type] || TYPE_STYLE.misc;
          return '<button data-id="' + esc(e.id) + '"><i style="background:' + st.color + '"></i>' +
            '<span class="mono">' + esc(shorten(e.full, 46)) + "</span>" +
            '<span class="muted small">' + esc(st.jp) + " / 関連" + degree(e.id) + "</span></button>";
        }).join("");
        sRes.hidden = false;
        sRes.querySelectorAll("button").forEach(function (b) {
          b.addEventListener("click", function () {
            var id = b.getAttribute("data-id");
            addNode(id);
            selected = id;
            sRes.hidden = true;
            sIn.value = "";
            updateCount(); renderSidebar(); settleAndFit(120);
          });
        });
      }, 250);
    });
    document.addEventListener("click", function (ev) {
      if (!sRes.contains(ev.target) && ev.target !== sIn) sRes.hidden = true;
    });

    /* --- キャンバス操作 --- */
    var dragNode = null, panStart = null, moved = false;

    canvas.addEventListener("mousedown", function (ev) {
      hideMenu();
      var rect = canvas.getBoundingClientRect();
      var sx = ev.clientX - rect.left, sy = ev.clientY - rect.top;
      var id = nodeAt(sx, sy);
      moved = false;
      if (id && ev.button === 0) {
        dragNode = id;
        nodes[id].pinned = true;
      } else if (ev.button === 0) {
        panStart = { x: ev.clientX, y: ev.clientY, ox: view.ox, oy: view.oy };
      }
    });
    window.addEventListener("mousemove", onMove);
    function onMove(ev) {
      if (!canvas || !canvas.isConnected) { window.removeEventListener("mousemove", onMove); return; }
      var rect = canvas.getBoundingClientRect();
      var sx = ev.clientX - rect.left, sy = ev.clientY - rect.top;
      if (dragNode && nodes[dragNode]) {
        moved = true;
        var w = screenToWorld(sx, sy);
        nodes[dragNode].x = w[0];
        nodes[dragNode].y = w[1];
        reheat();
        return;
      }
      if (panStart) {
        moved = true;
        view.ox = panStart.ox + (ev.clientX - panStart.x);
        view.oy = panStart.oy + (ev.clientY - panStart.y);
        return;
      }
      var id = nodeAt(sx, sy);
      hovered = id;
      canvas.style.cursor = id ? "pointer" : "default";
      if (id) {
        tipEl.textContent = (TYPE_STYLE[entities[id].type] || TYPE_STYLE.misc).jp + ": " + entities[id].full;
        tipEl.style.left = (sx + 14) + "px";
        tipEl.style.top = (sy + 14) + "px";
        tipEl.hidden = false;
      } else tipEl.hidden = true;
    }
    window.addEventListener("mouseup", function up() {
      if (!canvas || !canvas.isConnected) { window.removeEventListener("mouseup", up); return; }
      dragNode = null;
      panStart = null;
      saveSoon();
    });
    canvas.addEventListener("click", function (ev) {
      if (moved) return;
      var rect = canvas.getBoundingClientRect();
      var id = nodeAt(ev.clientX - rect.left, ev.clientY - rect.top);
      selected = id;
      renderSidebar();
    });
    canvas.addEventListener("dblclick", function (ev) {
      var rect = canvas.getBoundingClientRect();
      var id = nodeAt(ev.clientX - rect.left, ev.clientY - rect.top);
      if (id) {
        selected = id;
        notifyExpand(expandNode(id, null));
        updateCount(); renderSidebar();
      }
    });
    canvas.addEventListener("contextmenu", function (ev) {
      ev.preventDefault();
      var rect = canvas.getBoundingClientRect();
      var id = nodeAt(ev.clientX - rect.left, ev.clientY - rect.top);
      if (id) { selected = id; renderSidebar(); showMenu(ev.clientX, ev.clientY, id); }
      else hideMenu();
    });
    canvas.addEventListener("wheel", function (ev) {
      ev.preventDefault();
      var rect = canvas.getBoundingClientRect();
      var sx = ev.clientX - rect.left, sy = ev.clientY - rect.top;
      var factor = ev.deltaY < 0 ? 1.15 : 1 / 1.15;
      var ns = Math.max(0.1, Math.min(4, view.scale * factor));
      var w = screenToWorld(sx, sy);
      view.ox = sx - w[0] * ns;
      view.oy = sy - w[1] * ns;
      view.scale = ns;
    }, { passive: false });
    window.addEventListener("keydown", function onKey(ev) {
      if (!canvas || !canvas.isConnected) { window.removeEventListener("keydown", onKey); return; }
      if ((ev.key === "Delete" || ev.key === "Backspace") && selected &&
          document.activeElement && document.activeElement.tagName !== "INPUT") {
        removeNode(selected);
        updateCount(); renderSidebar();
      }
    });

    function updateCount() {
      var el = document.getElementById("g-count");
      if (el) el.textContent = Object.keys(nodes).length + " ノード / " + shownEdges().length + " 辺";
    }
    var countTimer = setInterval(function () {
      if (!canvas || !canvas.isConnected) { clearInterval(countTimer); return; }
      updateCount();
    }, 1000);
  };
})();
