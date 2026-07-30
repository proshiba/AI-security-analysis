/* マルウェア解析ブラウザ — analysis-results/ を検索・閲覧する静的UI。
 * データは generate_ui_data.py が生成する data.js (window.MALDB) を使う。 */
(function () {
  "use strict";

  var DB = window.MALDB;
  var app = document.getElementById("app");
  var PAGE_SIZE = 100;

  if (!DB) {
    app.innerHTML = '<div class="empty">data.js が見つかりません。<code>python3 ui/generate_ui_data.py</code> を実行してから再読み込みしてください。</div>';
    return;
  }

  /* ---------- 前処理 ---------- */

  var INTEL = DB.intel || { campaigns: [], labels: {}, code_links: [], source: null };
  var intelById = {};       // campaign候補 id -> campaign
  var intelByCase = {};     // sha256 -> [campaign候補id]
  var codeByCase = {};      // sha256 -> [{sha256, count}]
  INTEL.campaigns.forEach(function (g) {
    intelById[g.id] = g;
    g.members.forEach(function (sha) {
      (intelByCase[sha] = intelByCase[sha] || []).push(g.id);
    });
  });
  INTEL.code_links.forEach(function (l) {
    (codeByCase[l[0]] = codeByCase[l[0]] || []).push({ sha256: l[1], count: l[2] });
    (codeByCase[l[1]] = codeByCase[l[1]] || []).push({ sha256: l[0], count: l[2] });
  });
  Object.keys(codeByCase).forEach(function (sha) {
    codeByCase[sha].sort(function (a, b) { return b.count - a.count; });
  });

  var casesBySha = {};
  var iocRows = []; // フラット化した IOC 行
  DB.cases.forEach(function (c) {
    casesBySha[c.sha256] = c;
    c._search = [
      c.sha256, c.family, familyLabel(c.family), c.version_key,
      c.campaign_type, c.file_name, c.file_type, c.reported_signature,
      (c.tags || []).join(" "), (c.collections || []).join(" "),
      (c.c2 || []).join(" "),
      c.iocs.map(function (e) { return e.value; }).join(" "),
      c.history.map(function (h) { return (h.matched_patterns || []).join(" "); }).join(" "),
      (intelByCase[c.sha256] || []).join(" ")
    ].join("\n").toLowerCase();
    c.iocs.forEach(function (e) {
      iocRows.push({ ioc: e, sha256: c.sha256, family: c.family });
    });
  });

  /* ---------- 統合検索の索引 ---------- */

  // IOCは同じ値が複数ケースに出るため、値ごとに畳んで観測元を集約する。
  var iocIndex = {};   // 正規化値 -> {value, types[], roles[], confidences[], cases[]}
  iocRows.forEach(function (r) {
    var key = r.ioc.value.trim().toLowerCase();
    var e = iocIndex[key];
    if (!e) {
      e = iocIndex[key] = { value: r.ioc.value.trim(), types: [], roles: [], cases: [] };
    }
    if (e.types.indexOf(r.ioc.type) < 0) e.types.push(r.ioc.type);
    if (r.ioc.role && e.roles.indexOf(r.ioc.role) < 0) e.roles.push(r.ioc.role);
    if (e.cases.indexOf(r.sha256) < 0) e.cases.push(r.sha256);
  });
  // C2欄の値も検索対象に含める(IOC-LIST.mdに出ない構造化データ由来のものがある)
  DB.cases.forEach(function (c) {
    (c.c2 || []).forEach(function (v) {
      var key = String(v).trim().toLowerCase();
      var e = iocIndex[key];
      if (!e) {
        e = iocIndex[key] = { value: String(v).trim(), types: ["C2/通信"], roles: [], cases: [] };
      }
      if (e.cases.indexOf(c.sha256) < 0) e.cases.push(c.sha256);
    });
  });
  var iocList = Object.keys(iocIndex).map(function (k) {
    var e = iocIndex[k];
    e.key = k;
    return e;
  });

  var familyList = Object.keys(DB.families).map(function (k) {
    var f = DB.families[k];
    var names = [f.label, f.title, k].concat(f.aliases || []).filter(Boolean);
    return { key: k, family: f, names: names, blob: names.join("\n").toLowerCase() };
  });

  var campaignList = INTEL.campaigns.map(function (g) {
    return {
      group: g,
      blob: [g.id, g.families.join(" "),
             g.shared_indicators.map(function (s) { return s.value; }).join(" ")]
        .join("\n").toLowerCase()
    };
  });

  // レポートから貼り付けた無害化表記(1.2.3[.]4 や hxxp://)も検索できるようにする
  function refang(s) {
    return String(s)
      .replace(/\[\.\]|\(\.\)/g, ".")
      .replace(/\[:\]/g, ":")
      .replace(/^h(x{2}|tt)p(s?):\/\//i, "http$2://")
      .replace(/\[at\]/gi, "@");
  }
  function normalizeQuery(s) { return refang(String(s || "").trim()).toLowerCase(); }

  // 完全一致 → 前方一致 → 部分一致 の順に並べるためのスコア
  function matchScore(hay, needle) {
    if (!hay) return -1;
    if (hay === needle) return 3;
    if (hay.indexOf(needle) === 0) return 2;
    return hay.indexOf(needle) >= 0 ? 1 : -1;
  }

  function searchAll(rawQuery, limit) {
    var q = normalizeQuery(rawQuery);
    var cap = limit || 25;
    var out = { query: q, families: [], iocs: [], cases: [], campaigns: [], exactCase: null };
    if (q.length < 2) return out;

    if (/^[0-9a-f]{64}$/.test(q) && casesBySha[q]) out.exactCase = casesBySha[q];

    familyList.forEach(function (f) {
      var best = -1;
      f.names.forEach(function (n) { best = Math.max(best, matchScore(n.toLowerCase(), q)); });
      if (best > 0) out.families.push({ item: f, score: best });
    });

    iocList.forEach(function (e) {
      var sc = matchScore(e.key, q);
      if (sc > 0) out.iocs.push({ item: e, score: sc * 10 + Math.min(e.cases.length, 9) });
    });

    var terms = q.split(/\s+/).filter(Boolean);
    DB.cases.forEach(function (c) {
      for (var i = 0; i < terms.length; i++) {
        if (c._search.indexOf(terms[i]) < 0) return;
      }
      var sc = c.sha256 === q ? 3 : (c.sha256.indexOf(q) === 0 ? 2 : 1);
      out.cases.push({ item: c, score: sc });
    });

    campaignList.forEach(function (g) {
      if (g.blob.indexOf(q) >= 0) out.campaigns.push({ item: g, score: 1 });
    });

    ["families", "iocs", "cases", "campaigns"].forEach(function (k) {
      out[k].sort(function (a, b) { return b.score - a.score; });
      out[k + "Total"] = out[k].length;
      out[k] = out[k].slice(0, cap).map(function (x) { return x.item; });
    });
    return out;
  }

  // 新着順の基準。追加日を主、履歴の解析日と初観測を補助に使う。
  function recencyKey(c) {
    var hist = (c.history && c.history[0] && c.history[0].analyzed_at) || "";
    return [c.added_at || "", hist, c.first_seen || ""].join("|");
  }

  function familyLabel(key) {
    var f = DB.families[key];
    return (f && (f.label || f.title)) || key;
  }

  // グラフ調査は横断ポータル(research_bench)側に集約したため、このUIは持たない。
  // ポータルのworkbenchはURL引数を取らないので、公開ルートである検索へ値を渡す。
  // 検索結果の「グラフで開く」からworkbenchのグラフへ入れる。
  var PORTAL_BASE = "https://proshiba.github.io/research_bench/";

  function portalSearchUrl(value) {
    return PORTAL_BASE + "#/search/" + encodeURIComponent(value);
  }

  // iframe埋め込み時にポータル内でネストしないよう、常に最上位で開く。
  function portalLink(value, text, extraClass, title) {
    return '<a class="' + (extraClass || "") + '" target="_top"' +
      ' title="' + esc(title || "ポータルのグラフ調査で開く") + '"' +
      ' href="' + esc(portalSearchUrl(value)) + '">' + text + "</a>";
  }

  // 成果物ファイル・結果ディレクトリへのリンク。GitHub Pages等で成果物本体を
  // 同梱しない配信では、DB.repo が示すGitHub上の該当パスへ向ける。
  // 検出できなければリポジトリ直下配信を想定した相対パスへフォールバックする。
  var REPO = DB.repo || null;
  function fileUrl(path, isDir) {
    if (REPO && REPO.html_base) {
      return REPO.html_base + "/" + (isDir ? "tree" : "blob") + "/" + REPO.branch + "/" + path;
    }
    return "../" + path;
  }

  /* ---------- ユーティリティ ---------- */

  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function shortSha(sha) { return sha.slice(0, 12) + "…"; }
  function fmtSize(n) {
    if (n === null || n === undefined) return "";
    if (n > 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + " MB";
    if (n > 1024) return (n / 1024).toFixed(1) + " KB";
    return n + " B";
  }
  function confClass(conf) {
    var s = String(conf || "").toLowerCase();
    if (/確認|高|confirmed|observed|verified/.test(s) && !/未確認|unverified/.test(s)) return "green";
    if (/中|inferred|documented|推定/.test(s)) return "amber";
    if (/低|未検証|unverified|candidate/.test(s)) return "red";
    return "";
  }
  function confBadge(conf) {
    if (!conf) return "";
    return '<span class="badge ' + confClass(conf) + '">' + esc(conf) + "</span>";
  }

  var toastEl = null, toastTimer = null;
  function toast(msg) {
    if (!toastEl) {
      toastEl = document.createElement("div");
      toastEl.className = "toast";
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toastEl.classList.remove("show"); }, 1600);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        function () { toast("コピーしました"); },
        function () { fallbackCopy(text); }
      );
    } else fallbackCopy(text);
  }
  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); toast("コピーしました"); }
    catch (e) { toast("コピーできませんでした"); }
    document.body.removeChild(ta);
  }
  window.__copy = copyText; // onclick 用

  /* ---------- 最小Markdownレンダラ ---------- */

  function mdInline(s) {
    s = esc(s);
    // コードスパンを先に退避
    var codes = [];
    s = s.replace(/`([^`]+)`/g, function (_, code) {
      codes.push(code);
      return "\u0000" + (codes.length - 1) + "\u0000";
    });
    s = s.replace(/\[([^\]]+)\]\(<?([^)>\s]+)>?\)/g, function (_, t, u) {
      if (/^https?:\/\//.test(u)) {
        return '<a href="' + u + '" target="_blank" rel="noopener noreferrer">' + t + "</a>";
      }
      return t;
    });
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/\u0000(\d+)\u0000/g, function (_, i) { return "<code>" + codes[+i] + "</code>"; });
    return s;
  }

  function renderMarkdown(text) {
    var lines = text.split(/\r?\n/);
    var out = [];
    var i = 0;
    while (i < lines.length) {
      var line = lines[i];
      if (/^\s*<!--/.test(line)) { i++; continue; }
      var fence = line.match(/^```/);
      if (fence) {
        var code = [];
        i++;
        while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i++; }
        i++;
        out.push("<pre><code>" + esc(code.join("\n")) + "</code></pre>");
        continue;
      }
      var h = line.match(/^(#{1,6})\s+(.*)$/);
      if (h) {
        var lv = h[1].length;
        out.push("<h" + lv + ">" + mdInline(h[2]) + "</h" + lv + ">");
        i++;
        continue;
      }
      if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) { out.push("<hr>"); i++; continue; }
      if (/^\s*\|/.test(line) && i + 1 < lines.length && /^\s*\|[\s\-|:]+\|?\s*$/.test(lines[i + 1])) {
        var head = splitRow(line);
        i += 2;
        var rows = [];
        while (i < lines.length && /^\s*\|/.test(lines[i])) { rows.push(splitRow(lines[i])); i++; }
        var t = "<table><thead><tr>" + head.map(function (c) { return "<th>" + mdInline(c) + "</th>"; }).join("") + "</tr></thead><tbody>";
        rows.forEach(function (r) {
          t += "<tr>" + r.map(function (c) { return "<td>" + mdInline(c) + "</td>"; }).join("") + "</tr>";
        });
        out.push(t + "</tbody></table>");
        continue;
      }
      if (/^\s*[-*]\s+/.test(line)) {
        var items = [];
        while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
          items.push("<li>" + mdInline(lines[i].replace(/^\s*[-*]\s+/, "")) + "</li>");
          i++;
        }
        out.push("<ul>" + items.join("") + "</ul>");
        continue;
      }
      if (/^\s*\d+\.\s+/.test(line)) {
        var oitems = [];
        while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
          oitems.push("<li>" + mdInline(lines[i].replace(/^\s*\d+\.\s+/, "")) + "</li>");
          i++;
        }
        out.push("<ol>" + oitems.join("") + "</ol>");
        continue;
      }
      if (/^\s*>/.test(line)) {
        var q = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) {
          q.push(mdInline(lines[i].replace(/^\s*>\s?/, "")));
          i++;
        }
        out.push("<blockquote>" + q.join("<br>") + "</blockquote>");
        continue;
      }
      if (!line.trim()) { i++; continue; }
      var para = [];
      while (i < lines.length && lines[i].trim() &&
             !/^(#{1,6})\s|^```|^\s*\||^\s*[-*]\s+|^\s*\d+\.\s+|^\s*>/.test(lines[i])) {
        para.push(mdInline(lines[i]));
        i++;
      }
      out.push("<p>" + para.join("<br>") + "</p>");
    }
    return '<div class="md">' + out.join("\n") + "</div>";
  }
  function splitRow(line) {
    return line.trim().replace(/^\||\|$/g, "").split("|").map(function (c) { return c.trim(); });
  }

  /* ---------- ルーティング ---------- */

  function parseHash() {
    var hash = location.hash.replace(/^#\/?/, "");
    var qIdx = hash.indexOf("?");
    var query = {};
    if (qIdx >= 0) {
      hash.slice(qIdx + 1).split("&").forEach(function (kv) {
        if (!kv) return;
        var p = kv.split("=");
        query[decodeURIComponent(p[0])] = decodeURIComponent(p.slice(1).join("=") || "");
      });
      hash = hash.slice(0, qIdx);
    }
    var parts = hash.split("/").filter(Boolean);
    return { parts: parts, query: query };
  }

  function buildHash(parts, query) {
    var h = "#/" + parts.join("/");
    var qs = Object.keys(query || {})
      .filter(function (k) { return query[k] !== "" && query[k] !== null && query[k] !== undefined; })
      .map(function (k) { return encodeURIComponent(k) + "=" + encodeURIComponent(query[k]); })
      .join("&");
    return qs ? h + "?" + qs : h;
  }

  function route() {
    if (typeof hideSuggest === "function") hideSuggest();
    var r = parseHash();
    var page = r.parts[0] || "dashboard";
    document.querySelectorAll(".nav a").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("data-nav") === page);
    });
    window.scrollTo(0, 0);
    try {
      if (page === "dashboard") return viewDashboard();
      if (page === "families") return viewFamilies();
      if (page === "cases") return viewCases(r.query);
      if (page === "iocs") return viewIocs(r.query);
      if (page === "search") return viewSearch(r.query);
      if (page === "intel" && r.parts[1]) return viewIntelDetail(decodeURIComponent(r.parts[1]));
      if (page === "intel") return viewIntelList(r.query);
      if (page === "family" && r.parts[1]) return viewFamily(r.parts[1], r.query);
      if (page === "case" && r.parts[1]) return viewCase(r.parts[1]);
      viewDashboard();
    } catch (e) {
      app.innerHTML = '<div class="empty">表示中にエラーが発生しました: ' + esc(e.message) + "</div>";
      throw e;
    }
  }

  /* ---------- ダッシュボード ---------- */

  function viewDashboard() {
    var s = DB.stats;
    var famList = Object.keys(DB.families).map(function (k) { return DB.families[k]; });
    famList.sort(function (a, b) { return b.case_count - a.case_count; });

    // 新着一覧は全ケースを対象にする。analysis_history.yaml は一括解析だと
    // レコードが付かず網羅率が3割程度なので、履歴だけを見ると直近の解析が
    // 一覧から丸ごと抜け落ちる。追加日(added_at)を主キーにし、履歴があれば
    // 解析日とキャンペーンを併記する。
    var recent = DB.cases.slice().sort(function (a, b) {
      return recencyKey(b).localeCompare(recencyKey(a));
    }).slice(0, 12);

    var html = '<h1 class="page-title">マルウェア解析ダッシュボード</h1>' +
      '<p class="page-sub">AIセキュリティ解析リポジトリの公開成果物(ケース・IOC・検知ルール・解析履歴)を横断的に閲覧できます。</p>' +
      '<div class="stat-grid">' +
      statCard(s.case_total, "解析ケース (SHA-256)") +
      statCard(s.family_total, "マルウェアファミリ") +
      statCard(s.ioc_total, "IOCエントリ") +
      statCard(s.rule_total, "YARA / Sigma ルール") +
      statCard(s.history_total, "解析履歴レコード") +
      '<a class="stat-card" href="#/intel" style="text-decoration:none"><div class="num">' + esc(s.campaign_candidates || 0) +
      '</div><div class="lbl">campaign相関候補 →</div></a>' +
      "</div>";

    html += '<div class="section"><h2>ケース数上位のファミリ <a class="small" href="#/families">すべて表示 →</a></h2><div class="family-grid">' +
      famList.slice(0, 12).map(familyCard).join("") + "</div></div>";

    html += '<div class="section"><h2>最近追加されたケース <a class="small" href="' +
      buildHash(["cases"], { sort: "added_desc" }) + '">すべて表示 →</a></h2>' +
      '<div class="tbl-wrap"><table class="tbl"><thead><tr>' +
      "<th>追加日</th><th>解析日</th><th>ファミリ</th><th>検体</th><th>キャンペーン / チェーン</th><th>主なC2</th></tr></thead><tbody>";
    recent.forEach(function (c) {
      var h = c.history[0];
      html += "<tr><td class='nowrap mono'>" + esc(c.added_at || "") + "</td>" +
        "<td class='nowrap mono small'>" + esc(h ? h.analyzed_at : "―") + "</td>" +
        "<td class='nowrap'><a href='#/family/" + esc(c.family) + "'>" + esc(familyLabel(c.family)) + "</a></td>" +
        "<td class='mono'><a href='#/case/" + c.sha256 + "'>" + shortSha(c.sha256) + "</a></td>" +
        "<td class='mono small'>" + esc(c.campaign_type || (h && h.campaign_type) || "") + "</td>" +
        "<td class='mono small'>" + (c.c2 || []).slice(0, 2).map(esc).join("<br>") + "</td></tr>";
    });
    html += "</tbody></table>" +
      '<div class="muted small" style="margin-top:6px">追加日はケースがリポジトリへ入った日です。解析日は ' +
      "<code>analysis_history.yaml</code> に履歴がある場合だけ表示します(一括解析では履歴が付かないことがあります)。</div></div>";
    app.innerHTML = html;
  }

  function statCard(num, label) {
    return '<div class="stat-card"><div class="num">' + esc(num) + '</div><div class="lbl">' + esc(label) + "</div></div>";
  }

  function familyCard(f) {
    var badges = ['<span class="badge accent">' + f.case_count + " ケース</span>"];
    if (f.rules.length) badges.push('<span class="badge green">' + f.rules.length + " ルール</span>");
    if (f.aliases) badges.push('<span class="badge">' + esc(f.aliases) + "</span>");
    return '<a class="family-card" href="#/family/' + esc(f.key) + '">' +
      '<div class="name">' + esc(f.label || f.key) + "</div>" +
      '<div class="key">' + esc(f.key) + "</div>" +
      '<div class="meta">' + badges.join("") + "</div></a>";
  }

  /* ---------- ファミリ一覧 ---------- */

  function viewFamilies() {
    var famList = Object.keys(DB.families).map(function (k) { return DB.families[k]; });
    famList.sort(function (a, b) { return b.case_count - a.case_count || a.key.localeCompare(b.key); });
    var html = '<h1 class="page-title">マルウェアファミリ一覧</h1>' +
      '<p class="page-sub">全 ' + famList.length + ' ファミリ。カードを選ぶと概要・OSINT・検知ルール・ケース一覧を表示します。</p>' +
      '<div class="family-grid">' + famList.map(familyCard).join("") + "</div>";
    app.innerHTML = html;
  }

  /* ---------- ケース検索 ---------- */

  function caseFilterOptions() {
    var fams = {}, camps = {}, cols = {};
    DB.cases.forEach(function (c) {
      fams[c.family] = true;
      if (c.campaign_type) camps[c.campaign_type] = true;
      (c.collections || []).forEach(function (col) { cols[col] = true; });
    });
    return {
      families: Object.keys(fams).sort(),
      campaigns: Object.keys(camps).sort(),
      collections: Object.keys(cols).sort()
    };
  }

  function filterCases(q) {
    var query = (q.q || "").toLowerCase().split(/\s+/).filter(Boolean);
    return DB.cases.filter(function (c) {
      if (q.family && c.family !== q.family) return false;
      if (q.campaign && c.campaign_type !== q.campaign) return false;
      if (q.collection && (c.collections || []).indexOf(q.collection) < 0) return false;
      if (q.c2 === "1" && !(c.c2 && c.c2.length)) return false;
      for (var i = 0; i < query.length; i++) {
        if (c._search.indexOf(query[i]) < 0) return false;
      }
      return true;
    });
  }

  function sortCases(list, mode) {
    var sorted = list.slice();
    if (mode === "added_desc") {
      sorted.sort(function (a, b) { return recencyKey(b).localeCompare(recencyKey(a)); });
      return sorted;
    }
    if (mode === "family") {
      sorted.sort(function (a, b) { return a.family.localeCompare(b.family) || (b.first_seen || "").localeCompare(a.first_seen || ""); });
    } else if (mode === "seen_asc") {
      sorted.sort(function (a, b) { return (a.first_seen || "9999").localeCompare(b.first_seen || "9999"); });
    } else {
      sorted.sort(function (a, b) { return (b.first_seen || "").localeCompare(a.first_seen || ""); });
    }
    return sorted;
  }

  function viewCases(q) {
    var opts = caseFilterOptions();
    var matched = sortCases(filterCases(q), q.sort);
    var page = Math.max(1, parseInt(q.page || "1", 10) || 1);
    var pages = Math.max(1, Math.ceil(matched.length / PAGE_SIZE));
    if (page > pages) page = pages;
    var slice = matched.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

    var html = '<h1 class="page-title">ケース検索</h1>' +
      '<p class="page-sub">SHA-256、ファミリ、キャンペーン種別、C2、IOC値、ファイル名、タグを横断検索できます。</p>';

    html += '<div class="filterbar">' +
      '<input type="search" id="f-q" placeholder="検索語 (スペース区切りでAND)" value="' + esc(q.q || "") + '">' +
      selectBox("f-family", "ファミリ: すべて", opts.families.map(function (k) { return [k, familyLabel(k) + " (" + k + ")"]; }), q.family) +
      selectBox("f-campaign", "キャンペーン: すべて", opts.campaigns.map(function (k) { return [k, k]; }), q.campaign) +
      selectBox("f-collection", "コレクション: すべて", opts.collections.map(function (k) { return [k, k]; }), q.collection) +
      '<label class="small"><input type="checkbox" id="f-c2"' + (q.c2 === "1" ? " checked" : "") + "> C2記録あり</label>" +
      selectBox("f-sort", "", [["added_desc", "追加が新しい順"], ["seen_desc", "初観測が新しい順"], ["seen_asc", "初観測が古い順"], ["family", "ファミリ順"]], q.sort || "seen_desc", true) +
      '<span class="count">' + matched.length + " / " + DB.cases.length + " 件</span></div>";

    html += caseTable(slice, true);
    html += pager(page, pages);
    app.innerHTML = html;

    var apply = function (resetPage) {
      var nq = {
        q: document.getElementById("f-q").value.trim(),
        family: document.getElementById("f-family").value,
        campaign: document.getElementById("f-campaign").value,
        collection: document.getElementById("f-collection").value,
        c2: document.getElementById("f-c2").checked ? "1" : "",
        sort: document.getElementById("f-sort").value === "seen_desc" ? "" : document.getElementById("f-sort").value,
        page: resetPage ? "" : q.page
      };
      location.hash = buildHash(["cases"], nq);
    };
    ["f-family", "f-campaign", "f-collection", "f-c2", "f-sort"].forEach(function (id) {
      document.getElementById(id).addEventListener("change", function () { apply(true); });
    });
    var qInput = document.getElementById("f-q");
    var timer = null;
    qInput.addEventListener("input", function () {
      clearTimeout(timer);
      timer = setTimeout(function () { apply(true); }, 350);
    });
    qInput.focus();
    var len = qInput.value.length;
    qInput.setSelectionRange(len, len);

    bindPager(function (p) {
      q.page = String(p);
      location.hash = buildHash(["cases"], q);
    });
  }

  function selectBox(id, emptyLabel, entries, current, noEmpty) {
    var html = '<select id="' + id + '">';
    if (!noEmpty) html += '<option value="">' + esc(emptyLabel) + "</option>";
    entries.forEach(function (e) {
      html += '<option value="' + esc(e[0]) + '"' + (current === e[0] ? " selected" : "") + ">" + esc(e[1]) + "</option>";
    });
    return html + "</select>";
  }

  function caseTable(list, withFamily) {
    if (!list.length) return '<div class="empty">条件に一致するケースがありません。</div>';
    var html = '<div class="tbl-wrap"><table class="tbl"><thead><tr>' +
      "<th>SHA-256</th>" + (withFamily ? "<th>ファミリ</th>" : "") +
      "<th>版</th><th>キャンペーン / チェーン</th><th>ファイル名</th><th class='nowrap'>初観測</th>" +
      "<th class='num'>IOC</th><th class='num'>C2</th><th>履歴</th></tr></thead><tbody>";
    list.forEach(function (c) {
      var histDates = c.history.map(function (h) { return h.analyzed_at; });
      html += "<tr><td class='mono nowrap'><a href='#/case/" + c.sha256 + "'>" + shortSha(c.sha256) + "</a></td>" +
        (withFamily ? "<td class='nowrap'><a href='#/family/" + esc(c.family) + "'>" + esc(familyLabel(c.family)) + "</a></td>" : "") +
        "<td class='mono small nowrap'>" + esc(c.version_key === "unknown" ? "―" : c.version_key) + "</td>" +
        "<td class='mono small'>" + esc(c.campaign_type || "") + "</td>" +
        "<td class='small' style='word-break:break-all;max-width:260px'>" + esc(c.file_name || "") + "</td>" +
        "<td class='mono small nowrap'>" + esc((c.first_seen || "").slice(0, 10)) + "</td>" +
        "<td class='num'>" + c.iocs.length + "</td>" +
        "<td class='num'>" + (c.c2 ? c.c2.length : 0) + "</td>" +
        "<td class='mono small nowrap'>" + (histDates.length ? esc(histDates[0]) + (histDates.length > 1 ? " ほか" + (histDates.length - 1) + "件" : "") : "") + "</td></tr>";
    });
    return html + "</tbody></table></div>";
  }

  function pager(page, pages) {
    if (pages <= 1) return "";
    return '<div class="pager">' +
      '<button class="btn small" data-page="' + (page - 1) + '"' + (page <= 1 ? " disabled" : "") + ">前へ</button>" +
      '<span class="muted small">' + page + " / " + pages + " ページ</span>" +
      '<button class="btn small" data-page="' + (page + 1) + '"' + (page >= pages ? " disabled" : "") + ">次へ</button></div>";
  }
  function bindPager(go) {
    document.querySelectorAll(".pager .btn").forEach(function (b) {
      b.addEventListener("click", function () {
        if (!b.disabled) go(parseInt(b.getAttribute("data-page"), 10));
      });
    });
  }

  /* ---------- IOC検索 ---------- */

  function viewIocs(q) {
    var types = {};
    iocRows.forEach(function (r) { types[r.ioc.type] = true; });
    var query = (q.q || "").toLowerCase();
    var matched = iocRows.filter(function (r) {
      if (q.type && r.ioc.type !== q.type) return false;
      if (query && (r.ioc.value + " " + r.ioc.role + " " + r.sha256 + " " + r.family).toLowerCase().indexOf(query) < 0) return false;
      return true;
    });

    var page = Math.max(1, parseInt(q.page || "1", 10) || 1);
    var pages = Math.max(1, Math.ceil(matched.length / PAGE_SIZE));
    if (page > pages) page = pages;
    var slice = matched.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

    var html = '<h1 class="page-title">IOC検索</h1>' +
      '<p class="page-sub">各ケースの IOC-LIST.md から集約した ' + iocRows.length + ' 件のIOCを検索できます。IP・ドメイン単独条件は短寿命・誤検知が多いため、役割と確度を必ず確認してください。</p>';

    html += '<div class="filterbar">' +
      '<input type="search" id="i-q" placeholder="IOC値 / SHA-256 / ファミリで検索" value="' + esc(q.q || "") + '">' +
      selectBox("i-type", "種別: すべて", Object.keys(types).sort().map(function (t) { return [t, t]; }), q.type) +
      '<button class="btn small" id="i-copy">表示中の値をコピー</button>' +
      '<span class="count">' + matched.length + " 件</span></div>";

    html += '<div class="tbl-wrap"><table class="tbl"><thead><tr>' +
      "<th>種別</th><th>値</th><th>役割</th><th>確度</th><th>ファミリ</th><th>ケース</th><th></th></tr></thead><tbody>";
    slice.forEach(function (r) {
      html += "<tr><td class='nowrap'>" + esc(r.ioc.type) + "</td>" +
        "<td class='mono' style='word-break:break-all'><a href='javascript:void(0)' onclick='__copy(" + JSON.stringify(r.ioc.value) + ")' title='クリックでコピー'>" + esc(r.ioc.value) + "</a></td>" +
        "<td class='small'>" + esc(r.ioc.role) + "</td>" +
        "<td>" + confBadge(r.ioc.confidence) + "</td>" +
        "<td class='nowrap'><a href='#/family/" + esc(r.family) + "'>" + esc(familyLabel(r.family)) + "</a></td>" +
        "<td class='mono nowrap'><a href='#/case/" + r.sha256 + "'>" + shortSha(r.sha256) + "</a></td>" +
        "<td class='nowrap'>" + portalLink(r.ioc.value, "⊕", "btn small") + "</td></tr>";
    });
    html += "</tbody></table></div>" + pager(page, pages);
    app.innerHTML = html;

    document.getElementById("i-type").addEventListener("change", function () {
      location.hash = buildHash(["iocs"], { q: q.q, type: this.value });
    });
    var input = document.getElementById("i-q");
    var timer = null;
    input.addEventListener("input", function () {
      clearTimeout(timer);
      var v = input.value.trim();
      timer = setTimeout(function () {
        location.hash = buildHash(["iocs"], { q: v, type: q.type });
      }, 350);
    });
    input.focus();
    var len = input.value.length;
    input.setSelectionRange(len, len);
    document.getElementById("i-copy").addEventListener("click", function () {
      var values = [];
      var seen = {};
      matched.forEach(function (r) {
        if (!seen[r.ioc.value]) { seen[r.ioc.value] = true; values.push(r.ioc.value); }
      });
      copyText(values.join("\n"));
    });
    bindPager(function (p) {
      location.hash = buildHash(["iocs"], { q: q.q, type: q.type, page: String(p) });
    });
  }

  /* ---------- 統合検索 ---------- */

  function viewSearch(q) {
    var raw = q.q || "";
    var res = searchAll(raw, 25);
    var total = (res.familiesTotal || 0) + (res.iocsTotal || 0) +
                (res.casesTotal || 0) + (res.campaignsTotal || 0);

    var html = '<h1 class="page-title">検索</h1>' +
      '<p class="page-sub">SHA-256・MD5・SHA-1、IPアドレス、ドメイン、URL、接続先、マルウェアファミリ名・別名、' +
      'キャンペーン候補、ファイル名、タグ、コレクションを横断して検索します。' +
      '無害化表記（<code>1.2.3[.]4</code>、<code>hxxp://</code>）もそのまま貼り付けられます。</p>';

    html += '<div class="filterbar">' +
      '<input type="search" id="gs-q" placeholder="例: 45.66.228.114 ／ ftp.vilimorin.com ／ AgentTesla ／ 3f091457" value="' + esc(raw) + '">' +
      '<span class="count">' + (raw.trim().length < 2 ? "2文字以上で検索" : total + " 件") + "</span></div>";

    if (raw.trim().length >= 2 && total === 0) {
      html += '<div class="empty">「' + esc(raw) + '」に一致する項目がありません。' +
        '<br><span class="small">ハッシュは先頭一致でも探せます。IOCは値の一部でも一致します。</span></div>';
    }

    if (res.exactCase) {
      html += '<div class="section"><h2>完全一致した検体</h2>' +
        '<div class="behavior-item"><span class="lbl mono"><a href="#/case/' + res.exactCase.sha256 + '">' +
        esc(res.exactCase.sha256) + '</a></span> ' +
        '<span class="badge accent">' + esc(familyLabel(res.exactCase.family)) + "</span>" +
        '<div class="ev">SHA-256が完全一致しました。ケースページへ移動できます。</div></div></div>';
    }

    if (res.families.length) {
      html += '<div class="section"><h2>マルウェアファミリ (' + res.familiesTotal + ")</h2>" +
        '<div class="family-grid">' + res.families.map(function (f) {
          return familyCard(f.family);
        }).join("") + "</div></div>";
    }

    if (res.iocs.length) {
      html += '<div class="section"><h2>IOC・通信先 (' + res.iocsTotal + ")" +
        (res.iocsTotal > res.iocs.length ? ' <span class="muted small">上位' + res.iocs.length + '件を表示</span>' : "") +
        '</h2><div class="tbl-wrap"><table class="tbl"><thead><tr>' +
        "<th>種別</th><th>値</th><th>役割</th><th class='num'>観測ケース</th><th>ファミリ</th><th></th></tr></thead><tbody>";
      res.iocs.forEach(function (e) {
        var fams = {};
        e.cases.forEach(function (sha) {
          var c = casesBySha[sha];
          if (c) fams[c.family] = true;
        });
        var famKeys = Object.keys(fams);
        html += "<tr><td class='nowrap small'>" + esc(e.types.join("、")) + "</td>" +
          "<td class='mono' style='word-break:break-all'><a href='javascript:void(0)' onclick='__copy(" + JSON.stringify(e.value) + ")' title='クリックでコピー'>" + esc(e.value) + "</a></td>" +
          "<td class='small'>" + esc(e.roles.slice(0, 2).join("、")) + "</td>" +
          "<td class='num'>" + e.cases.length + "</td>" +
          "<td class='small nowrap'>" + famKeys.slice(0, 2).map(function (k) {
            return '<a href="#/family/' + esc(k) + '">' + esc(familyLabel(k)) + "</a>";
          }).join(", ") + (famKeys.length > 2 ? " ほか" + (famKeys.length - 2) : "") + "</td>" +
          "<td class='nowrap'>" + portalLink(e.value, "⊕", "btn small") + "</td></tr>";
      });
      html += "</tbody></table></div>" +
        '<div class="muted small" style="margin-top:6px">「観測ケース」はこの値が出てくる検体ケースの数です。値をクリックするとコピー、⊕ でポータルのグラフ調査へ渡します。</div></div>';
    }

    if (res.cases.length) {
      html += '<div class="section"><h2>検体ケース (' + res.casesTotal + ")" +
        (res.casesTotal > res.cases.length
          ? ' <a class="small" href="' + buildHash(["cases"], { q: raw }) + '">ケース検索で全' + res.casesTotal + '件を見る →</a>'
          : "") +
        "</h2>" + caseTable(sortCases(res.cases, "added_desc"), true) + "</div>";
    }

    if (res.campaigns.length) {
      html += '<div class="section"><h2>キャンペーン相関候補 (' + res.campaignsTotal + ")</h2>" +
        '<div class="tbl-wrap"><table class="tbl"><thead><tr>' +
        "<th>candidate</th><th>ファミリ</th><th class='num'>case</th><th>確度</th></tr></thead><tbody>";
      res.campaigns.forEach(function (g) {
        var c = g.group;
        html += "<tr><td class='mono nowrap'><a href='#/intel/" + encodeURIComponent(c.id) + "'>" + esc(intelShort(c.id)) + "</a></td>" +
          "<td class='nowrap'>" + c.families.map(function (f) {
            return '<a href="#/family/' + esc(f) + '">' + esc(familyLabel(f)) + "</a>";
          }).join(", ") + "</td>" +
          "<td class='num'>" + (c.member_count || c.members.length) + "</td>" +
          "<td>" + confBadge(c.confidence) + "</td></tr>";
      });
      html += "</tbody></table></div></div>";
    }

    app.innerHTML = html;

    var input = document.getElementById("gs-q");
    var timer = null;
    input.addEventListener("input", function () {
      clearTimeout(timer);
      var v = input.value;
      timer = setTimeout(function () { location.hash = buildHash(["search"], { q: v.trim() }); }, 350);
    });
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
  }

  /* ---------- キャンペーン相関 (intelligence) ---------- */

  function intelShort(id) { return id.replace(/^correlated-/, ""); }

  function viewIntelList(q) {
    var query = (q.q || "").toLowerCase();
    var list = INTEL.campaigns.filter(function (g) {
      if (!query) return true;
      var blob = (g.id + " " + g.families.join(" ") + " " +
        g.shared_indicators.map(function (s) { return s.value; }).join(" ") + " " +
        g.members.join(" ")).toLowerCase();
      return blob.indexOf(query) >= 0;
    });
    list = list.slice().sort(function (a, b) {
      return (b.member_count || 0) - (a.member_count || 0) || a.id.localeCompare(b.id);
    });

    var html = '<h1 class="page-title">キャンペーン相関候補</h1>' +
      '<p class="page-sub">共有インフラ・共有指標に基づくcampaign候補 ' + INTEL.campaigns.length + ' 群' +
      (INTEL.source ? '（生成元: <code>' + esc(INTEL.source) + "</code>）" : "") +
      '。同一アクターへの帰属を意味しません。グラフでのpivot調査は' +
      ' <a target="_top" href="' + esc(PORTAL_BASE) + '">横断ポータル</a> に集約しています。</p>';

    html += '<div class="filterbar">' +
      '<input type="search" id="il-q" placeholder="candidate ID / ファミリ / 指標値 / SHA-256 で検索" value="' + esc(q.q || "") + '">' +
      '<span class="count">' + list.length + " / " + INTEL.campaigns.length + " 群</span></div>";

    if (!list.length) {
      html += '<div class="empty">条件に一致する候補がありません。</div>';
    } else {
      html += '<div class="tbl-wrap"><table class="tbl"><thead><tr>' +
        "<th>candidate</th><th>ファミリ</th><th class='num'>case</th><th>確度</th><th>共有指標</th><th class='num'>スコア</th><th></th></tr></thead><tbody>";
      list.forEach(function (g) {
        var inds = g.shared_indicators.slice(0, 2).map(function (s) {
          return '<span class="chip">' + esc(shortenText(s.value, 36)) + " ×" + s.support + "</span>";
        }).join("");
        if (g.shared_indicators.length > 2) inds += '<span class="muted small"> ほか' + (g.shared_indicators.length - 2) + "件</span>";
        html += "<tr><td class='mono nowrap'><a href='#/intel/" + encodeURIComponent(g.id) + "'>" + esc(intelShort(g.id)) + "</a></td>" +
          "<td class='nowrap'>" + g.families.map(function (f) {
            return '<a href="#/family/' + esc(f) + '">' + esc(familyLabel(f)) + "</a>";
          }).join(", ") + "</td>" +
          "<td class='num'>" + (g.member_count || g.members.length) + "</td>" +
          "<td>" + confBadge(g.confidence) + "</td>" +
          "<td>" + inds + "</td>" +
          "<td class='num'>" + esc(g.max_pair_score === null || g.max_pair_score === undefined ? "" : g.max_pair_score) + "</td>" +
          "<td class='nowrap'>" + portalLink(g.id, "⊕", "btn small") + "</td></tr>";
      });
      html += "</tbody></table></div>";
    }

    // コード類似サマリ
    html += '<div class="section"><h2>ファミリ横断のコード完全一致リンク</h2>' +
      '<p class="page-sub small">意味トークン列SHA-256の完全一致関数を共有するケースペア(' + INTEL.code_links.length +
      '件、library様の広域一致group除外済み)。各ケースページとグラフ調査に「コード類似」として表示されます。</p></div>';

    app.innerHTML = html;
    var input = document.getElementById("il-q");
    var timer = null;
    input.addEventListener("input", function () {
      clearTimeout(timer);
      var v = input.value.trim();
      timer = setTimeout(function () { location.hash = buildHash(["intel"], { q: v }); }, 350);
    });
    if (q.q) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
  }

  function shortenText(s, n) { s = String(s); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

  function viewIntelDetail(id) {
    var g = intelById[id];
    if (!g) { app.innerHTML = '<div class="empty">campaign候補が見つかりません: ' + esc(id) + "</div>"; return; }
    var members = g.members.map(function (sha) { return casesBySha[sha]; }).filter(Boolean);

    var html = '<div class="case-head">' +
      '<div class="muted small"><a href="#/intel">キャンペーン相関候補</a></div>' +
      '<h1 class="page-title mono" style="font-size:18px">' + esc(g.id) + "</h1>" +
      '<div style="margin-top:6px">' +
      '<span class="badge accent">' + members.length + " ケース</span> " +
      confBadge(g.confidence) + " " +
      (g.classification ? '<span class="badge mono">' + esc(g.classification) + "</span> " : "") +
      (g.max_pair_score !== null && g.max_pair_score !== undefined ? '<span class="badge">最大pairスコア ' + g.max_pair_score + "</span> " : "") +
      portalLink(g.id, "ポータルのグラフで調査", "btn small") +
      "</div>" +
      '<dl class="kv">' +
      kvRow("ファミリ", g.families.map(function (f) {
        return '<a href="#/family/' + esc(f) + '">' + esc(familyLabel(f)) + "</a>";
      }).join(", ")) +
      kvRow("生成元", g.path ? '<a class="mono small" target="_blank" rel="noopener noreferrer" href="' + esc(fileUrl(g.path, true)) + '">' + esc(g.path) + "</a>" : null) +
      "</dl></div>";

    if (g.shared_indicators.length) {
      html += '<div class="section"><h2>共有指標 (' + g.shared_indicators.length + ')</h2><div class="tbl-wrap"><table class="tbl"><thead><tr>' +
        "<th>種別</th><th>値</th><th class='num'>case支持数</th><th></th></tr></thead><tbody>";
      g.shared_indicators.forEach(function (s) {
        html += "<tr><td class='nowrap'>" + esc(s.type) + "</td>" +
          "<td class='mono' style='word-break:break-all'><a href='javascript:void(0)' onclick='__copy(" + JSON.stringify(s.value) + ")' title='クリックでコピー'>" + esc(s.value) + "</a></td>" +
          "<td class='num'>" + esc(s.support) + "</td>" +
          "<td class='nowrap'>" + portalLink(s.value, "⊕", "btn small") + "</td></tr>";
      });
      html += "</tbody></table></div></div>";
    }

    html += '<div class="section"><h2>相関ケース (' + members.length + ")</h2>" + caseTable(members, true) + "</div>";

    if (g.rules.length) {
      html += '<div class="section"><h2>検知ルール (' + g.rules.length + ")</h2>" +
        g.rules.map(function (r) { return ruleBlock(r); }).join("") + "</div>";
    }

    if (g.limitations.length) {
      html += '<div class="section"><h2>制約</h2><div class="md"><ul>' +
        g.limitations.map(function (l) { return "<li>" + esc(l) + "</li>"; }).join("") + "</ul></div></div>";
    }

    if (g.readme) {
      html += '<div class="section"><h2>候補レポート (README.md)</h2>' + renderMarkdown(g.readme) + "</div>";
    }

    app.innerHTML = html;
    bindRuleCopy(app);
  }

  /* ---------- ファミリ詳細 ---------- */

  function viewFamily(key, q) {
    var f = DB.families[key];
    if (!f) { app.innerHTML = '<div class="empty">ファミリが見つかりません: ' + esc(key) + "</div>"; return; }
    var cases = DB.cases.filter(function (c) { return c.family === key; });
    var versions = {}, campaigns = {}, c2set = {};
    var lastAnalyzed = "";
    var iocCount = 0;
    cases.forEach(function (c) {
      versions[c.version_key] = (versions[c.version_key] || 0) + 1;
      if (c.campaign_type) campaigns[c.campaign_type] = (campaigns[c.campaign_type] || 0) + 1;
      (c.c2 || []).forEach(function (v) { c2set[v] = true; });
      iocCount += c.iocs.length;
      c.history.forEach(function (h) { if (h.analyzed_at > lastAnalyzed) lastAnalyzed = h.analyzed_at; });
    });
    var caseRules = [];
    cases.forEach(function (c) {
      c.rules.forEach(function (r) { caseRules.push({ rule: r, sha256: c.sha256 }); });
    });

    var tabs = [["cases", "ケース一覧 (" + cases.length + ")"]];
    if (f.rules.length || caseRules.length) tabs.push(["rules", "検知ルール (" + (f.rules.length + caseRules.length) + ")"]);
    var docOrder = ["readme", "osint", "technical", "versions", "campaigns", "behavior_c2"];
    docOrder.concat(Object.keys(f.docs).filter(function (dk) { return docOrder.indexOf(dk) < 0; }))
      .forEach(function (dk) {
        if (f.docs[dk]) tabs.push(["doc-" + dk, f.doc_titles[dk] || dk]);
      });
    var active = q.tab || "cases";
    if (!tabs.some(function (t) { return t[0] === active; })) active = "cases";

    var html = '<div class="family-head">' +
      '<h1 class="page-title">' + esc(f.label || key) + "</h1>" +
      (f.title && f.title !== f.label ? '<div class="muted">' + esc(f.title) + "</div>" : "") +
      '<div style="margin-top:10px">' +
      '<span class="badge accent">' + cases.length + " ケース</span> " +
      '<span class="badge mono">' + esc(key) + "</span> " +
      (f.aliases ? '<span class="badge">別名: ' + esc(f.aliases) + "</span> " : "") +
      (lastAnalyzed ? '<span class="badge green">最終解析 ' + esc(lastAnalyzed) + "</span> " : "") +
      '<span class="badge">' + iocCount + " IOC</span> " +
      '<span class="badge">' + (f.rules.length + caseRules.length) + " ルール</span> " +
      portalLink(f.label || key, "ポータルのグラフで調査", "btn small") +
      "</div>";
    var versionBadges = Object.keys(versions).sort().map(function (v) {
      return '<span class="chip">' + esc(v === "unknown" ? "版不明" : v) + " × " + versions[v] + "</span>";
    }).join("");
    var campaignBadges = Object.keys(campaigns).sort(function (a, b) { return campaigns[b] - campaigns[a]; })
      .map(function (cmp) { return '<span class="chip">' + esc(cmp) + " × " + campaigns[cmp] + "</span>"; }).join("");
    html += '<dl class="kv">' +
      "<dt>版の内訳</dt><dd>" + (versionBadges || "―") + "</dd>" +
      "<dt>キャンペーン / チェーン</dt><dd>" + (campaignBadges || "―") + "</dd>" +
      "<dt>記録済みC2</dt><dd>" + (Object.keys(c2set).length ? Object.keys(c2set).length + " 件 (各ケースページ参照)" : "―") + "</dd>" +
      "</dl></div>";

    html += '<div class="section"><div class="tabs">' + tabs.map(function (t) {
      return '<button data-tab="' + t[0] + '"' + (t[0] === active ? ' class="active"' : "") + ">" + esc(t[1]) + "</button>";
    }).join("") + "</div><div id='tab-body'></div></div>";
    app.innerHTML = html;

    document.querySelectorAll(".tabs button").forEach(function (b) {
      b.addEventListener("click", function () {
        location.hash = buildHash(["family", key], { tab: b.getAttribute("data-tab"), q: q.q });
      });
    });

    var body = document.getElementById("tab-body");
    if (active === "cases") {
      var query = (q.q || "").toLowerCase().split(/\s+/).filter(Boolean);
      var filtered = cases.filter(function (c) {
        for (var i = 0; i < query.length; i++) if (c._search.indexOf(query[i]) < 0) return false;
        return true;
      });
      filtered = sortCases(filtered, "seen_desc");
      body.innerHTML = '<div class="filterbar">' +
        '<input type="search" id="fam-q" placeholder="このファミリ内を検索 (SHA-256 / C2 / キャンペーン等)" value="' + esc(q.q || "") + '">' +
        '<span class="count">' + filtered.length + " / " + cases.length + " 件</span></div>" +
        caseTable(filtered, false);
      var input = document.getElementById("fam-q");
      var timer = null;
      input.addEventListener("input", function () {
        clearTimeout(timer);
        var v = input.value.trim();
        timer = setTimeout(function () {
          location.hash = buildHash(["family", key], { tab: "cases", q: v });
        }, 350);
      });
      if (q.q) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
    } else if (active === "rules") {
      var rhtml = "";
      if (f.rules.length) {
        rhtml += "<h3>ファミリ共通ルール</h3>" + f.rules.map(function (r) { return ruleBlock(r); }).join("");
      }
      if (caseRules.length) {
        rhtml += "<h3>ケース固有ルール</h3>" + caseRules.map(function (cr) {
          return ruleBlock(cr.rule, cr.sha256);
        }).join("");
      }
      body.innerHTML = rhtml || '<div class="empty">このファミリの検知ルールは登録されていません。</div>';
      bindRuleCopy(body);
    } else if (active.indexOf("doc-") === 0) {
      var dk = active.slice(4);
      body.innerHTML = f.docs[dk] ? renderMarkdown(f.docs[dk]) : '<div class="empty">文書がありません。</div>';
    }
  }

  function ruleBlock(rule, sha) {
    return '<div class="rule-block"><div class="rule-head">' +
      '<span class="badge ' + (rule.kind === "yara" ? "amber" : "accent") + '">' + rule.kind.toUpperCase() + "</span>" +
      "<code>" + esc(rule.name) + "</code>" +
      (sha ? '<a class="small mono" href="#/case/' + sha + '">' + shortSha(sha) + "</a>" : "") +
      '<button class="btn small" style="margin-left:auto" data-copy-rule>コピー</button>' +
      "</div><pre><code>" + esc(rule.text) + "</code></pre></div>";
  }
  function bindRuleCopy(root) {
    root.querySelectorAll("[data-copy-rule]").forEach(function (b) {
      b.addEventListener("click", function () {
        var pre = b.closest(".rule-block").querySelector("pre");
        copyText(pre.textContent);
      });
    });
  }

  /* ---------- ケース詳細 ---------- */

  function viewCase(sha) {
    var c = casesBySha[sha];
    if (!c) {
      // 前方一致でも検索できるようにする
      var hit = DB.cases.filter(function (x) { return x.sha256.indexOf(sha) === 0; });
      if (hit.length === 1) { location.replace("#/case/" + hit[0].sha256); return; }
      app.innerHTML = '<div class="empty">ケースが見つかりません: <code>' + esc(sha) + "</code></div>";
      return;
    }
    var f = DB.families[c.family];

    var html = '<div class="case-head">' +
      '<div class="muted small"><a href="#/family/' + esc(c.family) + '">' + esc(familyLabel(c.family)) + "</a> のケース</div>" +
      '<div class="hash-line"><code>' + c.sha256 + "</code>" +
      '<button class="btn small" onclick="__copy(' + JSON.stringify(c.sha256) + ')">コピー</button>' +
      portalLink(c.sha256, "ポータルのグラフで調査", "btn small") + "</div>" +
      '<div style="margin-top:8px">' +
      (c.campaign_type ? '<span class="badge accent mono">' + esc(c.campaign_type) + "</span> " : "") +
      (c.version_key !== "unknown" ? '<span class="badge green">版 ' + esc(c.version_key) + "</span> " : '<span class="badge">版不明</span> ') +
      (c.assessment.score !== null && c.assessment.score !== undefined
        ? '<span class="badge ' + (c.assessment.status === "complete" ? "green" : "amber") + '">解析充足度 ' + c.assessment.score + "/" + c.assessment.max + "</span> " : "") +
      (c.reported_signature ? '<span class="badge">提供元報告: ' + esc(c.reported_signature) + "</span>" : "") +
      "</div>";

    html += '<dl class="kv">' +
      kvRow("ファイル名", c.file_name ? '<span class="mono">' + esc(c.file_name) + "</span>" : null) +
      kvRow("形式 / サイズ", c.file_type ? esc(c.file_type) + (c.file_size ? " / " + fmtSize(c.file_size) : "") : null) +
      kvRow("初観測", c.first_seen ? '<span class="mono">' + esc(c.first_seen) + "</span>" : null) +
      kvRow("提供元", c.provider) +
      kvRow("タグ", c.tags.length ? c.tags.map(function (t) { return '<span class="chip">' + esc(t) + "</span>"; }).join("") : null) +
      kvRow("コレクション", c.collections.length ? c.collections.map(function (t) { return '<span class="chip">' + esc(t) + "</span>"; }).join("") : null) +
      kvRow("結果ディレクトリ", '<a class="mono small" target="_blank" rel="noopener noreferrer" href="' + esc(fileUrl(c.path, true)) + '">' + esc(c.path) + "</a>") +
      "</dl></div>";

    // C2
    if (c.c2 && c.c2.length) {
      html += '<div class="section"><h2>C2 / ネットワーク指標 (' + c.c2.length + ")</h2><div>" +
        c.c2.map(function (v) {
          return '<span class="chip"><a href="javascript:void(0)" onclick="__copy(' + JSON.stringify(v) + ')" title="クリックでコピー">' + esc(v) + "</a>" +
            " " + portalLink(v, "⊕") + "</span>";
        }).join("") +
        '<div class="muted small" style="margin-top:6px">値はケースのIOC一覧・解析履歴からの集約です。役割・確度は下のIOC表と履歴を参照してください。</div></div></div>';
    }

    // campaign相関・コード類似 (intelligence)
    var caseIntel = intelByCase[c.sha256] || [];
    var caseCode = codeByCase[c.sha256] || [];
    if (caseIntel.length || caseCode.length) {
      html += '<div class="section"><h2>相関インテリジェンス</h2>';
      if (caseIntel.length) {
        html += "<h3 style='font-size:13px;margin:8px 0 6px'>campaign相関候補</h3>" +
          caseIntel.map(function (gid) {
            var g = intelById[gid];
            if (!g) return "";
            return '<div class="behavior-item"><span class="lbl mono"><a href="#/intel/' + encodeURIComponent(gid) + '">' + esc(intelShort(gid)) + "</a></span> " +
              confBadge(g.confidence) +
              '<div class="ev">相関ケース' + g.members.length + "件 / 共有指標: " +
              g.shared_indicators.slice(0, 3).map(function (s) { return "<code>" + esc(shortenText(s.value, 40)) + "</code>"; }).join(" ") +
              "</div></div>";
          }).join("");
      }
      if (caseCode.length) {
        html += "<h3 style='font-size:13px;margin:12px 0 6px'>コード完全一致の類似ケース (" + caseCode.length + ")</h3>" +
          '<div class="tbl-wrap"><table class="tbl"><thead><tr><th>ケース</th><th>ファミリ</th><th class="num">一致関数group数</th></tr></thead><tbody>' +
          caseCode.slice(0, 15).map(function (l) {
            var o = casesBySha[l.sha256];
            return "<tr><td class='mono nowrap'><a href='#/case/" + l.sha256 + "'>" + shortSha(l.sha256) + "</a></td>" +
              "<td class='nowrap'>" + (o ? '<a href="#/family/' + esc(o.family) + '">' + esc(familyLabel(o.family)) + "</a>" : "") + "</td>" +
              "<td class='num'>" + l.count + "</td></tr>";
          }).join("") + "</tbody></table></div>" +
          (caseCode.length > 15 ? '<div class="muted small" style="margin-top:4px">上位15件のみ表示。全件はグラフ調査で確認できます。</div>' : "") +
          '<div class="muted small" style="margin-top:4px">意味トークン列SHA-256完全一致の共有関数group数。共通library・compiler生成コードでも一致し得ます。</div>';
      }
      html += "</div>";
    }

    // 挙動
    if (c.behaviors.length) {
      var groups = {};
      c.behaviors.forEach(function (b) {
        var g = b.category || "その他";
        (groups[g] = groups[g] || []).push(b);
      });
      html += '<div class="section"><h2>挙動・機能 (' + c.behaviors.length + ")</h2>";
      Object.keys(groups).forEach(function (g) {
        html += '<div class="behavior-group"><h4>' + esc(g) + "</h4>" +
          groups[g].map(function (b) {
            return '<div class="behavior-item"><span class="lbl">' + esc(b.label || b.id) + "</span> " + confBadge(b.confidence) +
              (b.evidence ? '<div class="ev">' + mdInline(b.evidence) + "</div>" : "") + "</div>";
          }).join("") + "</div>";
      });
      html += "</div>";
    }

    // 検体特徴
    if (c.characteristics.length) {
      html += '<div class="section"><h2>検体特徴 (' + c.characteristics.length + ')</h2><div class="tbl-wrap"><table class="tbl"><thead><tr>' +
        "<th>分類</th><th>特徴</th><th>値</th><th>確度</th><th>根拠</th></tr></thead><tbody>";
      c.characteristics.forEach(function (ch) {
        html += "<tr><td class='nowrap'>" + esc(ch.category || "") + "</td>" +
          "<td>" + esc(ch.label || ch.id) + "</td>" +
          "<td class='mono small' style='word-break:break-all'>" + esc(ch.value === "observed" ? "" : (ch.value || "")) + "</td>" +
          "<td>" + confBadge(ch.confidence) + "</td>" +
          "<td class='small'>" + mdInline(ch.evidence || "") + "</td></tr>";
      });
      html += "</tbody></table></div></div>";
    }

    // IOC
    html += '<div class="section"><h2>IOC一覧 (' + c.iocs.length + ")</h2>";
    if (c.iocs.length) {
      html += '<div style="margin-bottom:8px"><button class="btn small" id="c-ioc-copy">値を一括コピー</button></div>' +
        '<div class="tbl-wrap"><table class="tbl"><thead><tr>' +
        "<th>種別</th><th>値</th><th>役割</th><th>確度</th><th>根拠</th></tr></thead><tbody>";
      c.iocs.forEach(function (e) {
        html += "<tr><td class='nowrap'>" + esc(e.type) + "</td>" +
          "<td class='mono' style='word-break:break-all'><a href='javascript:void(0)' onclick='__copy(" + JSON.stringify(e.value) + ")' title='クリックでコピー'>" + esc(e.value) + "</a></td>" +
          "<td class='small'>" + esc(e.role) + "</td>" +
          "<td>" + confBadge(e.confidence) + "</td>" +
          "<td class='small'>" + esc(e.source) + "</td></tr>";
      });
      html += "</tbody></table></div>";
    } else {
      html += '<div class="empty">公開可能なIOCが登録されていません。' +
        (c.ioc_assessment ? "<br>評価: " + esc(c.ioc_assessment) : "") + "</div>";
    }
    html += "</div>";

    // 検知ルール
    var famRules = f ? f.rules : [];
    html += '<div class="section"><h2>検知ルール (YARA / Sigma)</h2>';
    if (c.rules.length) {
      html += c.rules.map(function (r) { return ruleBlock(r); }).join("");
    }
    if (famRules.length) {
      html += '<div class="muted small" style="margin:6px 0">ファミリ共通ルール ' + famRules.length + ' 件: <a href="' +
        buildHash(["family", c.family], { tab: "rules" }) + '">' + esc(familyLabel(c.family)) + " の検知ルールを見る →</a></div>";
    }
    if (!c.rules.length && !famRules.length) {
      html += '<div class="empty">このケース・ファミリに登録済みのルールはありません。ケースREADMEのYARA/Sigma材料の節を参照してください。</div>';
    }
    html += "</div>";

    // 解析履歴
    html += '<div class="section"><h2>解析履歴 (' + c.history.length + ")</h2>";
    if (c.history.length) {
      html += '<div class="timeline">' + c.history.map(function (h) {
        return '<div class="timeline-item">' +
          '<div><span class="date">' + esc(h.analyzed_at) + "</span> " +
          (h.campaign_type ? '<span class="badge accent mono">' + esc(h.campaign_type) + "</span> " : "") +
          (h.analysis_level ? '<span class="badge">' + esc(h.analysis_level) + "</span>" : "") + "</div>" +
          (h.matched_patterns && h.matched_patterns.length
            ? "<ul>" + h.matched_patterns.map(function (p) { return "<li>" + mdInline(p) + "</li>"; }).join("") + "</ul>" : "") +
          (h.c2 && h.c2.length ? "<div>C2: " + h.c2.map(function (v) { return '<span class="chip">' + esc(v) + "</span>"; }).join("") + "</div>" : "") +
          (h.notes ? '<div class="muted small">' + esc(h.notes) + "</div>" : "") +
          "</div>";
      }).join("") + "</div>";
    } else {
      html += '<div class="empty">analysis_history.yaml にこの検体の履歴レコードはありません(バッチ解析のみのケースなど)。</div>';
    }
    html += "</div>";

    // README
    if (c.docs.readme) {
      html += '<div class="section"><h2>ケースレポート (README.md)</h2>' + renderMarkdown(c.docs.readme) + "</div>";
    }

    // 成果物
    if (c.artifacts && c.artifacts.length) {
      html += '<div class="section"><h2>成果物ファイル (' + c.artifacts.length + ")</h2><div>" +
        c.artifacts.map(function (a) {
          return '<a class="chip" target="_blank" rel="noopener noreferrer" href="' + esc(fileUrl(c.path + "/" + a, false)) + '">' + esc(a) + "</a>";
        }).join("") + "</div></div>";
    }

    app.innerHTML = html;
    var copyBtn = document.getElementById("c-ioc-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        copyText(c.iocs.map(function (e) { return e.value; }).join("\n"));
      });
    }
    bindRuleCopy(app);
  }

  function kvRow(label, valueHtml) {
    if (!valueHtml) return "";
    return "<dt>" + esc(label) + "</dt><dd>" + valueHtml + "</dd>";
  }

  /* ---------- 起動 ---------- */

  /* ---------- ヘッダー検索(入力中の候補表示) ---------- */

  var gInput = document.getElementById("global-search-input");
  var gBox = document.getElementById("global-suggest");

  function hideSuggest() { if (gBox) { gBox.hidden = true; gBox.innerHTML = ""; } }

  function renderSuggest(raw) {
    if (!gBox) return;
    var res = searchAll(raw, 5);
    var total = (res.familiesTotal || 0) + (res.iocsTotal || 0) +
                (res.casesTotal || 0) + (res.campaignsTotal || 0);
    if (normalizeQuery(raw).length < 2) return hideSuggest();

    var rows = [];
    if (res.exactCase) {
      rows.push(suggestRow("#/case/" + res.exactCase.sha256, "検体",
        shortSha(res.exactCase.sha256), familyLabel(res.exactCase.family) + " / SHA-256完全一致"));
    }
    res.families.forEach(function (f) {
      rows.push(suggestRow("#/family/" + f.key, "ファミリ", f.family.label || f.key,
        f.family.case_count + " ケース"));
    });
    res.iocs.forEach(function (e) {
      rows.push(suggestRow(buildHash(["search"], { q: e.value }), e.types[0] || "IOC",
        e.value, e.cases.length + " ケースで観測"));
    });
    res.cases.forEach(function (c) {
      rows.push(suggestRow("#/case/" + c.sha256, "検体", shortSha(c.sha256),
        familyLabel(c.family) + (c.file_name ? " / " + c.file_name : "")));
    });
    res.campaigns.forEach(function (g) {
      rows.push(suggestRow("#/intel/" + encodeURIComponent(g.group.id), "キャンペーン",
        intelShort(g.group.id), (g.group.member_count || 0) + " ケース"));
    });

    if (!rows.length) {
      gBox.innerHTML = '<div class="gsg-empty">一致なし</div>';
    } else {
      gBox.innerHTML = rows.slice(0, 12).join("") +
        '<a class="gsg-all" href="' + buildHash(["search"], { q: raw.trim() }) + '">' +
        "すべての結果を見る (" + total + " 件) →</a>";
    }
    gBox.hidden = false;
  }

  function suggestRow(href, kind, label, sub) {
    return '<a class="gsg-row" href="' + esc(href) + '">' +
      '<span class="gsg-kind">' + esc(kind) + "</span>" +
      '<span class="gsg-label mono">' + esc(label) + "</span>" +
      '<span class="gsg-sub">' + esc(sub || "") + "</span></a>";
  }

  var gTimer = null;
  gInput.addEventListener("input", function () {
    clearTimeout(gTimer);
    var v = gInput.value;
    gTimer = setTimeout(function () { renderSuggest(v); }, 180);
  });
  gInput.addEventListener("focus", function () {
    if (gInput.value.trim().length >= 2) renderSuggest(gInput.value);
  });
  gInput.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") { hideSuggest(); gInput.blur(); }
  });
  document.addEventListener("click", function (ev) {
    if (gBox && !gBox.contains(ev.target) && ev.target !== gInput) hideSuggest();
  });

  document.getElementById("global-search").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var v = gInput.value.trim();
    clearTimeout(gTimer);   // 保留中の候補描画が後から開くのを防ぐ
    hideSuggest();
    // SHA-256が完全一致するときだけケースへ直行し、それ以外は統合検索へ送る
    if (/^[0-9a-f]{64}$/i.test(v) && casesBySha[v.toLowerCase()]) {
      location.hash = "#/case/" + v.toLowerCase();
    } else {
      location.hash = buildHash(["search"], { q: v });
    }
  });

  window.addEventListener("hashchange", route);
  route();
})();
