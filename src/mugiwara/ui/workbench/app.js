/* Mugiwara Security workbench — vanilla JS, hash-routed views over the local API. */
(function () {
  "use strict";

  var viewEl = document.getElementById("view");
  var toastsEl = document.getElementById("toasts");

  /* ---------- utilities ---------- */

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function el(html) {
    var t = document.createElement("template");
    t.innerHTML = html.trim();
    var node = t.content.firstElementChild;
    if (!node) { throw new Error("el(): template produced no element"); }
    return node;
  }

  /* One key/value row for .kv grids. Returns a fragment so BOTH spans land
     in the DOM (a bare el() keeps only the first root element). */
  function kvRow(key, value, mono) {
    var pair = document.createDocumentFragment();
    pair.appendChild(el("<span class='k'>" + esc(key) + "</span>"));
    pair.appendChild(el(
      "<span" + (mono ? " class='mono'" : "") + ">" + esc(value == null ? "" : value) + "</span>"
    ));
    return pair;
  }

  function toast(message, kind) {
    var node = el('<div class="toast ' + esc(kind || "") + '">' + esc(message) + "</div>");
    toastsEl.appendChild(node);
    setTimeout(function () { node.remove(); }, kind === "error" ? 8000 : 4500);
  }

  function api(path, options) {
    return fetch(path, options).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (payload) {
        if (!resp.ok) {
          var message = payload && payload.error ? payload.error : "Request failed (" + resp.status + ")";
          throw new Error(message);
        }
        return payload;
      });
    });
  }

  function fmtDate(iso) {
    if (!iso) { return "-"; }
    return String(iso).replace("T", " ").slice(0, 19);
  }

  function sevBadge(sev) {
    return '<span class="badge b-' + esc(String(sev).toLowerCase()) + '">' + esc(sev) + "</span>";
  }

  function statusBadge(status) {
    return '<span class="badge b-' + esc(String(status).toLowerCase()) + '">' +
      esc(String(status).replace("_", " ")) + "</span>";
  }

  function diffHtml(diff) {
    var pre = el('<pre class="diff"></pre>');
    String(diff).split("\n").forEach(function (line) {
      var span = document.createElement("span");
      if (/^\+\+\+|^---|^@@/.test(line)) { span.className = /^@@/.test(line) ? "hunk" : "meta"; }
      else if (line.indexOf("+") === 0) { span.className = "add"; }
      else if (line.indexOf("-") === 0) { span.className = "del"; }
      span.textContent = line.length ? line : " ";
      pre.appendChild(span);
      pre.appendChild(document.createTextNode("\n"));
    });
    return pre;
  }

  var PHASE_STAGES = [
    ["validating", "Collecting"],
    ["recon", "Reconnaissance"],
    ["discovery", "Discovery"],
    ["verification", "Verification"]
  ];

  function phaseStrip(phases, finished) {
    var strip = el('<div class="pipeline"></div>');
    var seen = phases || [];
    var lastIdx = -1;
    PHASE_STAGES.forEach(function (stage, i) {
      if (seen.indexOf(stage[0]) !== -1) { lastIdx = i; }
    });
    PHASE_STAGES.forEach(function (stage, i) {
      if (i) { strip.appendChild(el('<span class="pipe-arrow">──▶</span>')); }
      var cls = (i < lastIdx || finished) ? " done" : (i === lastIdx ? " active" : "");
      strip.appendChild(el(
        '<span class="phase' + cls + '"><span class="dot"></span>' + stage[1] + "</span>"
      ));
    });
    if (finished) {
      strip.appendChild(el('<span class="pipe-arrow">──▶</span>'));
      strip.appendChild(el('<span class="phase done"><span class="dot"></span>Complete</span>'));
    }
    return strip;
  }

  /* ---------- scan launcher ---------- */

  function scanLauncher(onStarted) {
    var wrap = el(
      '<div class="panel">' +
      "<h3>Scan a Project</h3>" +
      '<div class="hint">Analyze a local project directory you are authorized to test. ' +
      "Scans run through the same hardened engine as the CLI; nothing leaves this machine.</div>" +
      '<div style="height:12px"></div>' +
      '<div class="rowflex">' +
      '<div style="flex:2 1 320px"><label class="fieldlabel" for="scanpath">Project directory</label>' +
      '<input type="text" id="scanpath" placeholder="D:\\projects\\my-app or ~/projects/my-app" spellcheck="false"></div>' +
      '<button class="primary" id="startdir">Start Scan</button>' +
      "</div>" +
      '<div style="height:10px"></div>' +
      '<div class="rowflex">' +
      '<div><label class="fieldlabel" for="zipfile">…or upload a ZIP archive</label>' +
      '<input type="file" id="zipfile" accept=".zip,application/zip"></div>' +
      '<button id="startzip">Scan Uploaded ZIP</button>' +
      "</div>" +
      '<div class="hint" id="scanmsg" style="margin-top:10px"></div>' +
      "</div>"
    );

    function setMsg(text) {
      wrap.querySelector("#scanmsg").textContent = text || "";
    }

    wrap.querySelector("#startdir").addEventListener("click", function () {
      var path = wrap.querySelector("#scanpath").value.trim();
      if (!path) { setMsg("Enter an authorized project directory first."); return; }
      setMsg("Starting scan…");
      api("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "directory", target: path })
      }).then(function (state) {
        setMsg("");
        toast("Scan started.", "success");
        if (onStarted) { onStarted(state); }
      }).catch(function (err) { setMsg(err.message); toast(err.message, "error"); });
    });

    wrap.querySelector("#startzip").addEventListener("click", function () {
      var input = wrap.querySelector("#zipfile");
      var file = input.files && input.files[0];
      if (!file) { setMsg("Choose a .zip archive to upload."); return; }
      setMsg("Uploading archive…");
      fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/zip", "X-Filename": file.name },
        body: file
      }).then(function (resp) {
        return resp.json().then(function (payload) {
          if (!resp.ok) { throw new Error(payload && payload.error ? payload.error : "Upload rejected."); }
          return payload;
        });
      }).then(function (state) {
        setMsg("");
        input.value = "";
        toast("Archive accepted — scan started.", "success");
        if (onStarted) { onStarted(state); }
      }).catch(function (err) { setMsg(err.message); toast(err.message, "error"); });
    });

    return wrap;
  }

  function pollScan(scanId, onUpdate) {
    api("/api/scans/" + encodeURIComponent(scanId)).then(onUpdate).catch(function (err) {
      toast(err.message, "error");
    });
  }

  /* ---------- dashboard view ---------- */

  function renderDashboard() {
    viewEl.innerHTML = '<div class="loading">Loading…</div>';
    api("/api/state").then(function (state) {
      viewEl.innerHTML = "";
      var totals = state.totals || {};
      var cards = el('<div class="cards"></div>');
      [
        ["Persisted Reports", totals.reports || 0, "in the local report store", "var(--ocean)"],
        ["Total Findings", totals.findings || 0, "across all stored reports", "var(--red)"],
        ["Verified", totals.verified || 0, "proven by PoC execution", "var(--gold)"],
        ["Suspected", totals.suspected || 0, "awaiting dynamic verification", "var(--purple)"]
      ].forEach(function (d) {
        cards.appendChild(el(
          '<div class="card" style="--accent:' + d[3] + '"><div class="k">' + d[0] +
          '</div><div class="v">' + d[1] + '</div><div class="sub">' + esc(d[2]) + "</div></div>"
        ));
      });
      viewEl.appendChild(scanLauncher(function () { renderScans(); }));
      viewEl.appendChild(el('<h2 class="section">Recent Scans</h2>'));

      var recent = state.recent_reports || [];
      if (!recent.length) {
        viewEl.appendChild(el('<div class="empty">No scans yet. Start your first scan above — ' +
          "reports persist locally and appear here.</div>"));
      } else {
        var table = el('<table class="grid"><thead><tr><th>Report</th><th>Created</th>' +
          "<th>Target</th><th>Findings</th><th>Verified</th><th>Suspected</th></tr></thead><tbody></tbody></table>");
        recent.forEach(function (r) {
          table.tBodies[0].appendChild(el(
            "<tr><td class='mono'><a href='#/findings/" + encodeURIComponent(r.report_id) + "'>" +
            esc(r.report_id) + "</a></td>" +
            "<td class='mono'>" + esc(fmtDate(r.created_at)) + "</td>" +
            "<td class='mono'>" + esc(r.target_path) + "</td>" +
            "<td>" + r.total_findings + "</td><td>" + r.verified_count + "</td><td>" +
            r.suspected_count + "</td></tr>"
          ));
        });
        viewEl.appendChild(table);
      }
    }).catch(function (err) {
      viewEl.innerHTML = "";
      viewEl.appendChild(el('<div class="empty error">Failed to load state: ' + esc(err.message) + "</div>"));
    });
  }

  /* ---------- scans view ---------- */

  function renderScans() {
    viewEl.innerHTML = "";
    viewEl.appendChild(scanLauncher(startPolling));
    viewEl.appendChild(el('<h2 class="section">This Session</h2>'));

    function startPolling(state) {
      var box = el('<div class="panel" id="active-' + esc(state.scan_id) + '"></div>');
      viewEl.insertBefore(box, viewEl.children[1]);
      var poll = function () {
        pollScan(state.scan_id, function (snap) {
          drawProgress(box, snap);
          if (snap.status === "running") { setTimeout(poll, 1000); }
          else if (snap.status === "completed") {
            toast("Scan complete" + (snap.summary ? ": " + snap.summary.total_findings + " finding(s)." : "."), "success");
          } else {
            toast(snap.error || "Scan failed.", "error");
          }
        });
      };
      poll();
    }

    function drawProgress(box, snap) {
      box.innerHTML = "";
      var head = el('<div class="rowflex" style="justify-content:space-between"></div>');
      head.appendChild(el("<h3 style='margin:0'>Scan <span class='mono'>" + esc(snap.scan_id) + "</span></h3>"));
      head.appendChild(el(statusBadge(snap.status)));
      box.appendChild(head);
      box.appendChild(el("<div class='mono' style='color:var(--ocean);font-size:12.5px;margin-top:6px'>" +
        esc(snap.target) + "</div>"));
      box.appendChild(phaseStrip(snap.phases, snap.status === "completed"));
      if (snap.phase_detail && snap.status === "running") {
        box.appendChild(el("<div class='hint mono'>" + esc(snap.phase_detail) + "</div>"));
      }
      if (snap.status === "error" && snap.error) {
        box.appendChild(el("<div class='empty' style='text-align:left;border-color:rgba(239,68,68,.5)'>" +
          esc(snap.error) + "</div>"));
      }
      if (snap.status === "completed") {
        var s = snap.summary;
        if (s) {
          box.appendChild(el("<div class='cards' style='margin-top:14px'>" +
            card("Findings", s.total_findings, "var(--red)") +
            card("Verified", s.verified_count, "var(--green)") +
            card("Suspected", s.suspected_count, "var(--purple)") +
            card("False Positives", s.false_positive_count, "var(--muted)") + "</div>"));
        }
        if (snap.persistence_note) {
          box.appendChild(el("<div class='hint' style='margin-top:8px'>" + esc(snap.persistence_note) + "</div>"));
        }
        if (snap.report_id) {
          box.appendChild(el(
            "<div style='margin-top:12px'><a class='btn' href='#/findings/" +
            encodeURIComponent(snap.report_id) + "'>Open report " + esc(snap.report_id) + "</a></div>"
          ));
        }
      }
    }

    function card(k, v, color) {
      return "<div class='card' style='--accent:" + color + ";margin-bottom:0'><div class='k'>" +
        k + "</div><div class='v'>" + v + "</div></div>";
    }

    api("/api/state").then(function (state) {
      var scans = state.scans || [];
      if (!scans.length) {
        viewEl.appendChild(el('<div class="empty">No scans launched from the browser in this session yet. ' +
          "CLI scans keep working exactly as before.</div>"));
        return;
      }
      var table = el('<table class="grid"><thead><tr><th>Scan</th><th>Target</th><th>Status</th>' +
        "<th>Report</th></tr></thead><tbody></tbody></table>");
      scans.forEach(function (s) {
        table.tBodies[0].appendChild(el(
          "<tr><td class='mono'>" + esc(s.scan_id) + "</td><td class='mono'>" + esc(s.target) +
          "</td><td>" + statusBadge(s.status) + "</td><td class='mono'>" +
          (s.report_id
            ? "<a href='#/findings/" + encodeURIComponent(s.report_id) + "'>" + esc(s.report_id) + "</a>"
            : "-") +
          "</td></tr>"
        ));
      });
      viewEl.appendChild(table);
    }).catch(function (err) { toast(err.message, "error"); });
  }

  /* ---------- reports view ---------- */

  function exportMenu(reportId) {
    var menu = el('<span class="exportmenu"><button class="btn">Export ▾</button>' +
      '<span class="menu">' +
      "<a href='/api/reports/" + encodeURIComponent(reportId) + "/export?format=json'>JSON</a>" +
      "<a href='/api/reports/" + encodeURIComponent(reportId) + "/export?format=sarif'>SARIF</a>" +
      "<a href='/api/reports/" + encodeURIComponent(reportId) + "/export?format=markdown'>Markdown</a>" +
      "</span></span>");
    menu.querySelector("button").addEventListener("click", function (ev) {
      ev.stopPropagation();
      menu.classList.toggle("open");
    });
    document.addEventListener("click", function () { menu.classList.remove("open"); });
    return menu;
  }

  function renderReports() {
    viewEl.innerHTML = '<div class="loading">Loading…</div>';
    api("/api/reports").then(function (payload) {
      viewEl.innerHTML = "";
      viewEl.appendChild(el('<h2 class="section">Persisted Reports</h2>'));
      var reports = payload.reports || [];
      if (!reports.length) {
        viewEl.appendChild(el('<div class="empty">The report store is empty. Run a scan from the ' +
          "<a href='#/scans'>Scans</a> page or with <span class='mono'>mugiwara scan</span>.</div>"));
        return;
      }
      var table = el('<table class="grid"><thead><tr><th>Report ID</th><th>Created (UTC)</th>' +
        "<th>Target</th><th>Findings</th><th>Verified</th><th>Suspected</th><th>Actions</th></tr></thead>" +
        "<tbody></tbody></table>");
      reports.forEach(function (r) {
        var row = el(
          "<tr><td class='mono'><a href='#/findings/" + encodeURIComponent(r.report_id) + "'>" +
          esc(r.report_id) + "</a></td>" +
          "<td class='mono'>" + esc(fmtDate(r.created_at)) + "</td>" +
          "<td class='mono'>" + esc(r.target_path) + "</td>" +
          "<td>" + r.total_findings + "</td><td>" + r.verified_count + "</td><td>" +
          r.suspected_count + "</td></tr>"
        );
        var actions = el("<td></td>");
        actions.appendChild(exportMenu(r.report_id));
        var delBtn = el('<button class="danger" style="margin-left:8px">Delete</button>');
        delBtn.addEventListener("click", function () {
          if (!window.confirm("Delete report " + r.report_id + "? This cannot be undone.")) { return; }
          api("/api/reports/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ report: r.report_id })
          }).then(function () {
            toast("Report deleted.", "success");
            renderReports();
          }).catch(function (err) { toast(err.message, "error"); });
        });
        actions.appendChild(delBtn);
        row.appendChild(actions);
        table.tBodies[0].appendChild(row);
      });
      viewEl.appendChild(table);
    }).catch(function (err) {
      viewEl.innerHTML = "";
      viewEl.appendChild(el('<div class="empty">Failed to load reports: ' + esc(err.message) + "</div>"));
    });
  }

  /* ---------- findings / report detail view ---------- */

  function findingCard(finding) {
    var locText = finding.location
      ? finding.location.file_path + ":" + finding.location.start_line
      : "-";
    var card = el('<div class="finding"></div>');
    var head = el('<div class="finding-head"></div>');
    head.appendChild(el('<span class="title">' + esc(finding.title) + "</span>"));
    head.appendChild(el(sevBadge(finding.severity)));
    head.appendChild(el(statusBadge(finding.status)));
    head.appendChild(el('<span class="loc">' + esc(locText) + "</span>"));
    card.appendChild(head);

    var body = el('<div class="finding-body"></div>');
    body.appendChild(el("<p class='desc'>" + esc(finding.description || "") + "</p>"));

    var kv = el('<div class="kv"></div>');
    kv.appendChild(kvRow("Category", finding.category));
    kv.appendChild(kvRow("CWE", finding.cwe_id || "—"));
    kv.appendChild(kvRow("Location", locText, true));
    if (finding.cvss_score != null) {
      kv.appendChild(kvRow("CVSS", finding.cvss_score + " " + (finding.cvss_vector || ""), true));
    }
    kv.appendChild(kvRow("Status", finding.status));
    body.appendChild(kv);

    if (finding.location && finding.location.snippet) {
      body.appendChild(el("<details class='evbox'><summary>Code location snippet</summary>" +
        "<pre class='evidence'>" + esc(finding.location.snippet) + "</pre></details>"));
    }

    if (finding.remediation) {
      var rem = finding.remediation;
      body.appendChild(el("<h3 style='font-size:13px;margin:14px 0 6px;color:var(--gold)'>" +
        "Remediation guidance</h3>"));
      if (rem.explanation) {
        body.appendChild(el("<p class='desc'>" + esc(rem.explanation) + "</p>"));
      }
      if (rem.unified_diff) {
        body.appendChild(el("<details class='evbox' open><summary>Suggested patch (review before applying)</summary></details>"));
        var last = body.lastChild;
        last.after(diffHtml(rem.unified_diff));
      }
    }

    if (finding.evidence) {
      var ev = finding.evidence;
      body.appendChild(el("<h3 style='font-size:13px;margin:14px 0 6px;color:var(--red)'>" +
        "Verification evidence</h3>"));
      if (ev.reproduction_steps && ev.reproduction_steps.length) {
        var ol = el("<ol style='font-size:13px;line-height:1.7'></ol>");
        ev.reproduction_steps.forEach(function (step) {
          ol.appendChild(el("<li>" + esc(step) + "</li>"));
        });
        body.appendChild(ol);
      }
      [["HTTP request", ev.http_request], ["HTTP response", ev.http_response],
       ["Probe output", ev.stdout_log]].forEach(function (pair) {
        if (pair[1]) {
          body.appendChild(el("<details class='evbox'><summary>" + pair[0] + "</summary>" +
            "<pre class='evidence'>" + esc(pair[1]) + "</pre></details>"));
        }
      });
      body.appendChild(el("<div class='hint'>Canary token observed: " +
        (ev.canary_found ? "yes" : "no") + "</div>"));
    }

    head.addEventListener("click", function () { card.classList.toggle("open"); });
    card.appendChild(body);
    return card;
  }

  function fixPanel(reportId, envelope) {
    var verified = (envelope.scan.findings || []).filter(function (f) {
      return f.status === "VERIFIED" && f.evidence;
    });
    var panel = el('<div class="panel"><h3>Remediation</h3></div>');
    if (!verified.length) {
      panel.appendChild(el("<div class='hint'>No dynamically verified findings are eligible for " +
        "automated fixes in this report.</div>"));
      return panel;
    }
    panel.appendChild(el("<div class='hint'>" + verified.length +
      " verified finding(s) can be remediated. Patches are generated, applied to an isolated copy, " +
      "and proven by re-running the original PoC in the sandbox. Your working tree is never modified." +
      "</div>"));
    panel.appendChild(el("<div style='height:12px'></div>"));
    var btn = el('<button class="primary">Generate Fix Bundle</button>');
    btn.addEventListener("click", function () {
      btn.disabled = true;
      btn.textContent = "Running sea trials…";
      api("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ report: reportId })
      }).then(function (bundle) {
        btn.remove();
        renderFixResults(panel, bundle);
        toast("Fix bundle generated.", "success");
      }).catch(function (err) {
        btn.disabled = false;
        btn.textContent = "Generate Fix Bundle";
        toast(err.message, "error");
      });
    });
    panel.appendChild(btn);
    return panel;
  }

  var FIX_FLAVOR = {
    VERIFIED_FIXED: "Threat Defeated",
    NOT_FIXED: "Patch Rejected",
    FAILED: "Could Not Be Proven",
    APPLIED: "Awaiting Trial",
    PROPOSED: "Draft Only"
  };

  function renderFixResults(panel, bundle) {
    panel.appendChild(el('<h3 style="margin-top:18px">Sea-Trial Results</h3>'));
    (bundle.notes || []).forEach(function (n) {
      panel.appendChild(el("<div class='hint'>· " + esc(n) + "</div>"));
    });
    if (!(bundle.remediations || []).length) {
      panel.appendChild(el("<div class='empty'>No remediation attempts were made for this report.</div>"));
      return;
    }
    bundle.remediations.forEach(function (r) {
      var card = el('<div class="panel" style="margin-bottom:12px"></div>');
      var head = el("<div class='rowflex' style='align-items:center;gap:10px'></div>");
      head.appendChild(el("<strong style='flex:1 1 260px'>" + esc(r.title) + "</strong>"));
      head.appendChild(el("<span class='pill p-" + esc(String(r.status).toLowerCase()) + "'>" +
        esc(r.status) + "</span>"));
      head.appendChild(el("<span class='hint'>" + esc(FIX_FLAVOR[r.status] || "") + "</span>"));
      card.appendChild(head);
      if (r.location) {
        card.appendChild(el("<div class='mono' style='color:var(--ocean);font-size:12.5px;margin:8px 0'>" +
          esc(r.location) + "</div>"));
      }
      if (r.explanation) {
        card.appendChild(el("<p class='desc' style='margin:8px 0'>" + esc(r.explanation) + "</p>"));
      }
      if (r.unified_diff) {
        card.appendChild(diffHtml(r.unified_diff));
      }
      var ev = r.post_validation_evidence;
      if (ev) {
        var ok = r.status === "VERIFIED_FIXED";
        card.appendChild(el("<ul style='font-size:13px;line-height:1.8;margin:6px 0 0;padding-left:20px'>" +
          "<li style='color:var(--green)'>✓ Patched target booted in the isolated sandbox</li>" +
          "<li style='color:var(--green)'>✓ Original PoC re-executed verbatim</li>" +
          (ok
            ? "<li style='color:var(--green)'>✓ Canary token no longer observed — exploit no longer reproduces</li>"
            : "<li style='color:var(--red)'>✗ The exploit could not be disproven after patching</li>") +
          "</ul>"));
      }
      if (r.reason) {
        card.appendChild(el("<div class='hint' style='border-left:3px solid var(--panel-edge);" +
          "padding-left:10px;margin-top:8px'>" + esc(r.reason) + "</div>"));
      }
      panel.appendChild(card);
    });
    panel.appendChild(el("<div class='hint' style='margin-top:10px'>The original target was never " +
      "modified. Review each diff carefully before applying anything yourself.</div>"));
  }

  function renderFindings(reportId) {
    viewEl.innerHTML = '<div class="loading">Loading…</div>';
    api("/api/reports").then(function (payload) {
      var reports = payload.reports || [];
      if (!reports.length) {
        viewEl.innerHTML = "";
        viewEl.appendChild(el('<div class="empty">No reports yet — run a scan first.</div>'));
        return;
      }
      var targetId = reportId || reports[0].report_id;
      var known = reports.some(function (r) { return r.report_id === targetId; });
      if (!known) {
        viewEl.innerHTML = "";
        viewEl.appendChild(el('<div class="empty">Report not found in the store: ' +
          esc(targetId) + "</div>"));
        return;
      }
      return api("/api/reports/" + encodeURIComponent(targetId)).then(function (envelope) {
        viewEl.innerHTML = "";
        var scan = envelope.scan;

        var meta = el('<div class="panel"></div>');
        meta.appendChild(el("<h3>Report <span class='mono'>" + esc(envelope.report_id) + "</span></h3>"));
        var s = scan.summary;
        meta.appendChild(el("<div class='cards' style='margin-top:12px;margin-bottom:0'>" +
          cardCell("Critical", s.critical_count, "var(--red)") +
          cardCell("High", s.high_count, "#F97316") +
          cardCell("Medium", s.medium_count, "var(--gold)") +
          cardCell("Low", s.low_count, "var(--ocean)") +
          cardCell("Verified", s.verified_count, "var(--green)") +
          cardCell("Suspected", s.suspected_count, "var(--purple)") + "</div>"));
        meta.appendChild(el("<div class='kv' style='margin-top:14px;margin-bottom:0'>" +
          "<span class='k'>Target</span><span class='mono'>" + esc(scan.target_path) + "</span>" +
          "<span class='k'>Scanned at</span><span class='mono'>" +
          esc(fmtDate(scan.completed_at || envelope.created_at)) + "</span>" +
          "<span class='k'>Profile</span><span>" + esc(scan.scan_profile) + "</span>" +
          "<span class='k'>Origin</span><span>" + esc(envelope.target.origin) + "</span>" +
          "</div>"));
        viewEl.appendChild(meta);
        viewEl.appendChild(fixPanel(targetId, envelope));
        viewEl.appendChild(el('<h2 class="section">Findings (' + s.total_findings + ")</h2>"));

        if (!(scan.findings || []).length) {
          viewEl.appendChild(el('<div class="empty">No findings were reported for this target.</div>'));
          return;
        }
        scan.findings.forEach(function (f) {
          viewEl.appendChild(findingCard(f));
        });
      });
    }).catch(function (err) {
      viewEl.innerHTML = "";
      viewEl.appendChild(el('<div class="empty">Failed to load report: ' + esc(err.message) + "</div>"));
    });

    function cardCell(k, v, color) {
      return "<div class='card' style='--accent:" + color + ";margin-bottom:0'><div class='k'>" +
        k + "</div><div class='v'>" + v + "</div></div>";
    }
  }

  /* ---------- settings view ---------- */

  function renderSettings() {
    viewEl.innerHTML = '<div class="loading">Loading…</div>';
    api("/api/settings").then(function (cfg) {
      viewEl.innerHTML = "";
      viewEl.appendChild(el('<h2 class="section">Effective Configuration</h2>'));
      var grid = el('<div class="settingsgrid"></div>');
      [
        ["LLM Provider", cfg.provider],
        ["Model", cfg.model],
        ["Sandbox Mode", cfg.sandbox_mode],
        ["Scan Profile", cfg.profile],
        ["Dynamic Verification", cfg.verification_enabled ? "enabled" : "disabled"],
        ["Evidence In Reports", cfg.include_evidence ? "included" : "excluded"],
        ["Report Store", cfg.reports_dir]
      ].forEach(function (item) {
        grid.appendChild(el("<div class='setcard'><div class='k'>" + esc(item[0]) +
          "</div><div class='v'>" + esc(item[1]) + "</div></div>"));
      });
      viewEl.appendChild(grid);
      viewEl.appendChild(el(
        "<div class='panel' style='margin-top:22px'><h3>About</h3>" +
        "<div class='hint'>This workbench is an interface over your existing Mugiwara engine. " +
        "Configuration changes are made through <span class='mono'>mugiwara.yaml</span> or the CLI " +
        "(<span class='mono'>mugiwara config set …</span>) and take effect on restart. " +
        "The server binds to 127.0.0.1 only and never exposes the sandbox or Docker internals.</div></div>"
      ));
    }).catch(function (err) {
      viewEl.innerHTML = "";
      viewEl.appendChild(el('<div class="empty">Failed to load settings: ' + esc(err.message) + "</div>"));
    });
  }

  /* ---------- router ---------- */

  var ROUTES = {
    dashboard: [renderDashboard, "dashboard"],
    scans: [renderScans, "scans"],
    reports: [renderReports, "reports"],
    findings: [renderFindings, "findings"],
    settings: [renderSettings, "settings"]
  };

  function route() {
    var hash = window.location.hash.replace(/^#\/?/, "");
    var parts = hash.split("/");
    var name = ROUTES[parts[0]] ? parts[0] : "dashboard";
    var arg = parts.slice(1).join("/") || null;
    Object.keys(ROUTES).forEach(function (key) {
      var link = document.querySelector('[data-nav="' + key + '"]');
      if (link) { link.classList.toggle("active", key === name); }
    });
    ROUTES[name][0](arg);
    window.scrollTo(0, 0);
  }

  window.addEventListener("hashchange", route);
  route();
})();
