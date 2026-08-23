/**
 * Workbench DOM regression tests (browser-equivalent, jsdom).
 *
 * Loads the REAL index.html shell and the REAL app.js into jsdom and drives
 * the exact user flow that regressed: uploading a ZIP through the Scans view
 * ("Scan started"), then polling /api/scans/<id> while the progress panel
 * renders phases. Before the fix, the first poll snapshot crashed with:
 *
 *   TypeError: Failed to execute 'appendChild' on 'Node':
 *   parameter 1 is not of type 'Node'.
 *
 * because drawProgress() passed the statusBadge() STRING to appendChild().
 * The app swallowed that error into an error toast and stopped polling, so
 * no live progress ever rendered.
 *
 * Run: npm ci && npm run test:ui   (or: node --test tests/js/)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";

const ASSETS = new URL("../../src/mugiwara/ui/workbench/", import.meta.url);
const SHELL_HTML = readFileSync(new URL("index.html", ASSETS), "utf8");
const APP_JS = readFileSync(new URL("app.js", ASSETS), "utf8");

const BASE = "http://127.0.0.1:8420";
const SCAN_ID = "abc123def456";
const REPORT_ID = "20260824T101112-abcdef1234";

/* ------------------------------------------------------------- helpers */

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function makeServer(routes) {
  const calls = [];
  const fetch = (url, options) => {
    const parsed = new URL(url, BASE);
    calls.push({ method: (options && options.method) || "GET", path: parsed.pathname });
    const handler = routes[parsed.pathname];
    if (!handler) {
      return Promise.resolve(jsonResponse(404, { error: `no stub for ${parsed.pathname}` }));
    }
    return Promise.resolve(handler(parsed, options));
  };
  return { fetch, calls };
}

function queue(snaps) {
  let i = 0;
  return () => jsonResponse(200, snaps[Math.min(i++, snaps.length - 1)]);
}

function snapshotScan(overrides = {}) {
  return {
    scan_id: SCAN_ID,
    target: "C:\\Users\\dev\\AppData\\Local\\Temp\\mugiwara-ui-uploads\\8f2a-demo-app.zip",
    kind: "zip",
    phases: [],
    phase_detail: "",
    status: "running",
    error: null,
    report_id: null,
    persistence_note: null,
    summary: null,
    ...overrides,
  };
}

function boot({ hash = "#/scans", routes }) {
  const dom = new JSDOM(SHELL_HTML, {
    url: `${BASE}/${hash}`,
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const { window } = dom;
  const server = makeServer(routes);
  window.fetch = server.fetch;
  window.eval(APP_JS); // real app code, executed after the stubs are in place
  return { dom, window, document: window.document, server };
}

async function until(fn, label, ms = 8000) {
  const deadline = Date.now() + ms;
  let lastErr = null;
  while (Date.now() < deadline) {
    try {
      const value = fn();
      if (value) { return value; }
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`condition not met within ${ms}ms: ${label}${lastErr ? ` (${lastErr})` : ""}`);
}

/** Await a render milestone; if the UI swallowed a DOM crash into a toast,
 * surface that exact error instead of a plain timeout. */
async function expectRender(document, fn, label) {
  try {
    return await until(fn, label);
  } catch (err) {
    const crash = toastTexts(document).find((t) => /appendChild|not of type 'Node'/i.test(t));
    if (crash) {
      throw new Error(`render crashed instead of rendering "${label}" -> ${crash}`);
    }
    throw err;
  }
}

function toastTexts(document) {
  return [...document.querySelectorAll("#toasts .toast")].map((t) => t.textContent);
}

function assertNoDomErrors(document) {
  const bad = toastTexts(document).filter((t) => /appendChild|not of type 'Node'/i.test(t));
  assert.deepEqual(bad, [], "no appendChild/DOM failure may surface anywhere in the UI");
}

const EMPTY_STATE = {
  totals: { reports: 0, findings: 0, verified: 0, suspected: 0 },
  recent_reports: [],
  scans: [],
};

/* ------------------------------------------------------------ fixtures */

const COMPLETED_SCAN = snapshotScan({
  status: "completed",
  phases: ["validating", "recon", "discovery", "verification"],
  phase_detail: "suspected_findings=2",
  summary: {
    total_findings: 2,
    critical_count: 0,
    high_count: 1,
    medium_count: 1,
    low_count: 0,
    info_count: 0,
    verified_count: 1,
    suspected_count: 1,
    false_positive_count: 0,
  },
  report_id: REPORT_ID,
});

function reportEnvelope() {
  return {
    report_id: REPORT_ID,
    created_at: "2026-08-24T10:11:12+00:00",
    target: { origin: "archive" },
    scan: {
      target_path: "C:\\Users\\dev\\uploads\\demo-app.zip",
      scan_profile: "standard",
      completed_at: "2026-08-24T10:12:00+00:00",
      summary: COMPLETED_SCAN.summary,
      findings: [
        {
          title: "Dynamic SQL construction",
          description: "User input reaches a SQL statement.",
          category: "sql_injection",
          severity: "HIGH",
          cwe_id: "CWE-89",
          status: "VERIFIED",
          location: { file_path: "app/main.py", start_line: 15, snippet: "cursor.execute(q)" },
          cvss_score: 8.1,
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N",
          remediation: {
            explanation: "Use parameter binding.",
            unified_diff: "--- a/app/main.py\n+++ b/app/main.py\n@@ -15,1 +15,1 @@\n-old line\n+new line\n",
          },
          evidence: {
            reproduction_steps: ["step one"],
            http_request: null,
            http_response: null,
            stdout_log: null,
            canary_found: true,
            canary_token: "MUGIWARA_CANARY_test",
          },
        },
        {
          title: "Reflected value hint",
          description: "Suspected sink.",
          category: "cross_site_scripting",
          severity: "MEDIUM",
          cwe_id: "CWE-79",
          status: "SUSPECTED",
          location: { file_path: "app/views.py", start_line: 4 },
          evidence: null,
          remediation: null,
        },
      ],
    },
  };
}

/** A report where every finding is only SUSPECTED with no remediation —
 * exactly the UX hole this change closes (nothing to auto-fix, but the user
 * still needs an honest next action). */
function suspectedOnlyEnvelope() {
  const base = reportEnvelope();
  base.scan.findings = [
    {
      title: "Hardcoded API credential",
      description: "A credential literal is embedded in source.",
      category: "hardcoded_secret",
      severity: "HIGH",
      cwe_id: "CWE-798",
      status: "SUSPECTED",
      location: { file_path: "config/settings.py", start_line: 8 },
      evidence: null,
      remediation: null,
    },
    {
      title: "Reflected value hint",
      description: "Suspected sink.",
      category: "cross_site_scripting",
      severity: "MEDIUM",
      cwe_id: "CWE-79",
      status: "SUSPECTED",
      location: { file_path: "app/views.py", start_line: 4 },
      evidence: null,
      remediation: null,
    },
  ];
  return base;
}

function listingFor(envelope) {
  const findings = envelope.scan.findings;
  return {
    report_id: envelope.report_id,
    created_at: envelope.created_at,
    target_path: envelope.scan.target_path,
    total_findings: findings.length,
    verified_count: findings.filter((f) => f.status === "VERIFIED").length,
    suspected_count: findings.filter((f) => f.status === "SUSPECTED").length,
  };
}

function fixBundle(records) {
  return {
    schema: "mugiwara.fix-bundle",
    version: 1,
    notes: [],
    remediations: records,
  };
}

const VERIFIED_FIXED_RECORD = {
  title: "Dynamic SQL construction",
  finding_id: "f1",
  status: "VERIFIED_FIXED",
  location: "app/main.py:15",
  explanation: "Parameterized the query.",
  unified_diff: "--- a/app/main.py\n+++ b/app/main.py\n@@ -15,1 +15,1 @@\n-old line\n+new line\n",
  reason: "original exploit no longer reproduces against the patched target.",
  post_validation_evidence: { canary_found: false, canary_token: "MUGIWARA_CANARY_x" },
};

const NOT_FIXED_RECORD = {
  title: "Dynamic SQL construction",
  finding_id: "f1",
  status: "NOT_FIXED",
  location: "app/main.py:15",
  unified_diff: "--- a/app/main.py\n+++ b/app/main.py\n@@ -15,1 +15,1 @@\n-old line\n+new line\n",
  reason: "original exploit still reproduces: the canary token was observed after applying the patch.",
  post_validation_evidence: { canary_found: true, canary_token: "MUGIWARA_CANARY_x" },
};

const FAILED_RECORD = {
  title: "Reflected value hint",
  finding_id: "f2",
  status: "FAILED",
  location: "app/views.py:4",
  unified_diff: "--- a/app/views.py\n+++ b/app/views.py\n@@ -4,1 +4,1 @@\n-a\n+b\n",
  reason: "inconclusive: rerun claimed exploitation but the canary token was never observed.",
  post_validation_evidence: { canary_found: false, canary_token: "MUGIWARA_CANARY_x" },
};

/* --------------------------------------------------------------- tests */

test("regression: ZIP upload -> Scan started -> live phases render -> completed report link", async () => {
  const app = boot({
    hash: "#/scans",
    routes: {
      "/api/state": () => jsonResponse(200, EMPTY_STATE),
      "/api/scans": (_url, options) => {
        assert.equal(options.method, "POST");
        assert.equal(options.headers["Content-Type"], "application/zip");
        return Promise.resolve(jsonResponse(200, snapshotScan()));
      },
      [`/api/scans/${SCAN_ID}`]: queue([
        snapshotScan({ phases: ["validating"], phase_detail: "files_collected=12" }),
        snapshotScan({ phases: ["validating", "recon"], phase_detail: "files_collected=34" }),
        snapshotScan(
          { phases: ["validating", "recon", "discovery"], phase_detail: "suspected_findings=2" },
        ),
        snapshotScan({
          phases: ["validating", "recon", "discovery", "verification"],
          phase_detail: "probes_executed=1",
        }),
        COMPLETED_SCAN,
      ]),
    },
  });
  const { document, window, server } = app;

  // Simulate choosing a file in <input type="file"> and clicking the button.
  const input = document.getElementById("zipfile");
  assert.ok(input, "ZIP file input present");
  const archive = new window.File([new Uint8Array([0x50, 0x4b, 0x03, 0x04])], "demo-app.zip", {
    type: "application/zip",
  });
  Object.defineProperty(input, "files", { value: [archive], configurable: true });
  document.getElementById("startzip").click();

  await until(
    () => document.querySelector(`[id="active-${SCAN_ID}"]`),
    "progress panel inserted after scan start",
  );
  assert.ok(
    toastTexts(document).some((t) => t.includes("Archive accepted") && t.includes("scan started")),
    "honest 'Scan started' confirmation shown",
  );

  // First poll snapshot renders WITHOUT any appendChild exception (the regression).
  await expectRender(document, () => document.querySelector(".pipeline"), "phase strip rendered");
  for (const stage of ["Collecting", "Reconnaissance"]) {
    assert.match(document.querySelector(".pipeline").textContent, new RegExp(stage));
  }

  // Live updates keep arriving; final state renders Complete + report artifacts.
  const panelText = await until(
    () => {
      const box = document.querySelector(`[id="active-${SCAN_ID}"]`);
      return box && box.textContent.includes("Complete") ? box.textContent : null;
    },
    "completed scan renders the full pipeline",
  );
  for (const stage of ["Collecting", "Reconnaissance", "Discovery", "Verification", "Complete"]) {
    assert.ok(panelText.includes(stage), `pipeline shows "${stage}"`);
  }
  assert.ok(panelText.includes("completed"), "status badge shows completed");
  assert.ok(panelText.includes("Open report"), "report call-to-action rendered");

  const cardValues = [...document.querySelectorAll(`[id="active-${SCAN_ID}"] .card .v`)].map((n) =>
    n.textContent,
  );
  assert.deepEqual(cardValues, ["2", "1", "1", "0"], "summary cards show findings breakdown");

  const link = document.querySelector(`a[href="#/findings/${REPORT_ID}"]`);
  assert.ok(link, "link to persisted report rendered");

  // Progress messages stay free of source contents, secrets, tokens or PoCs.
  assert.ok(!panelText.includes("MUGIWARA_CANARY"));
  assert.ok(!panelText.includes("SELECT"));

  // Polling continued past the previously-crashing snapshot.
  const pollCalls = server.calls.filter((c) => c.path === `/api/scans/${SCAN_ID}`).length;
  assert.ok(pollCalls >= 5, `polled through every stage (got ${pollCalls} polls)`);

  assertNoDomErrors(document);
  app.dom.window.close();
});

test("failed scans render a visible honest failure state without exceptions", async () => {
  const ERROR_TEXT = "Engine rejected target: intake validation failed";
  const FAIL_ID = "err012abc789";
  const app = boot({
    hash: "#/scans",
    routes: {
      "/api/state": () => jsonResponse(200, EMPTY_STATE),
      "/api/scans": () =>
        Promise.resolve(jsonResponse(200, { ...snapshotScan(), scan_id: FAIL_ID })),
      [`/api/scans/${FAIL_ID}`]: queue([
        snapshotScan({ scan_id: FAIL_ID, phases: ["validating"] }),
        snapshotScan({
          scan_id: FAIL_ID,
          status: "error",
          phases: ["validating"],
          error: ERROR_TEXT,
        }),
      ]),
    },
  });
  const { document } = app;

  const pathInput = document.getElementById("scanpath");
  pathInput.value = "D:\\projects\\demo";
  document.getElementById("startdir").click();

  await expectRender(
    document,
    () => document.querySelector('[id^="active-"] .empty')?.textContent.includes(ERROR_TEXT),
    "failure block shows the engine error verbatim",
  );
  const badge = document.querySelector('[id^="active-"] .head .badge, [id^="active-"] span.badge');
  assert.ok(badge, "status badge rendered");
  assert.equal(badge.textContent.trim().toLowerCase(), "error");
  assert.ok(
    toastTexts(document).some((t) => t.includes(ERROR_TEXT)),
    "failure surfaced as an error toast too",
  );
  assertNoDomErrors(document);
  app.dom.window.close();
});

test("findings view renders badges, diff and evidence for a completed report", async () => {
  const envelope = reportEnvelope();
  const listingItem = {
    report_id: REPORT_ID,
    created_at: envelope.created_at,
    target_path: envelope.scan.target_path,
    total_findings: 2,
    verified_count: 1,
    suspected_count: 1,
  };
  const app = boot({
    hash: `#/findings/${REPORT_ID}`,
    routes: {
      "/api/reports": () => jsonResponse(200, { reports: [listingItem] }),
      [`/api/reports/${REPORT_ID}`]: () => jsonResponse(200, envelope),
    },
  });
  const { document } = app;

  await expectRender(document, () => document.querySelector(".finding"), "finding cards rendered");
  assert.ok(document.body.textContent.includes("Findings (2)"));

  const head = document.querySelector(".finding .finding-head");
  assert.ok(head.querySelector(".title").textContent.includes("Dynamic SQL construction"));
  assert.equal(head.textContent.includes("HIGH"), true, "severity badge text rendered as a node");
  assert.equal(head.textContent.includes("VERIFIED"), true, "status badge rendered as a node");
  assert.ok(head.querySelector(".badge.b-high"), "severity badge element present");
  assert.ok(head.querySelector(".badge.b-verified"), "status badge element present");

  const kv = document.querySelector(".finding .kv").textContent;
  assert.ok(kv.includes("CWE-89") && kv.includes("app/main.py:15"));

  const diff = document.querySelector(".finding pre.diff");
  assert.ok(diff, "remediation diff rendered via diffHtml");
  assert.ok(diff.querySelector("span.add").textContent.startsWith("+new line"));
  assert.ok(diff.querySelector("span.del").textContent.startsWith("-old line"));

  assert.ok(document.body.textContent.includes("Canary token observed: yes"));
  assert.ok(document.querySelector(".panel .primary"), "fix bundle entry point offered");

  assertNoDomErrors(document);
  app.dom.window.close();
});

test("dashboard tables build real table rows (template-parsed el())", async () => {
  const app = boot({
    hash: "#/dashboard",
    routes: {
      "/api/state": () =>
        jsonResponse(200, {
          totals: { reports: 1, findings: 2, verified: 1, suspected: 1 },
          recent_reports: [
            {
              report_id: REPORT_ID,
              created_at: "2026-08-24T10:11:12+00:00",
              target_path: "C:\\Users\\dev\\uploads\\demo-app.zip",
              total_findings: 2,
              verified_count: 1,
              suspected_count: 1,
            },
          ],
          scans: [],
        }),
    },
  });
  const { document } = app;

  const tbody = await until(
    () => document.querySelector("table.grid tbody"),
    "recent reports table rendered",
  );
  const rows = [...tbody.children];
  assert.equal(rows.length, 1);
  for (const row of rows) {
    assert.equal(row.tagName, "TR", "rows must be actual TR elements, not stripped text");
    assert.equal(row.querySelectorAll("td").length, 6);
  }
  assert.equal(rows[0].querySelector("td a").getAttribute("href"), `#/findings/${REPORT_ID}`);
  assertNoDomErrors(document);
  app.dom.window.close();
});

test("suspected-only report shows honest fix-unavailable guidance and can never trigger fixes", async () => {
  const envelope = suspectedOnlyEnvelope();
  let fixCalls = 0;
  const app = boot({
    hash: `#/findings/${REPORT_ID}`,
    routes: {
      "/api/reports": () => jsonResponse(200, { reports: [listingFor(envelope)] }),
      [`/api/reports/${REPORT_ID}`]: () => jsonResponse(200, envelope),
      "/api/fix": () => {
        fixCalls += 1;
        return jsonResponse(409, { error: "fix endpoint must never be hit for this report" });
      },
    },
  });
  const { document } = app;

  await expectRender(document, () => document.querySelector(".finding .fixna"), "fix-unavailable note rendered");

  const text = document.body.textContent;
  assert.ok(text.includes("Fix unavailable for this finding"), "'Fix unavailable' label shown");
  assert.ok(
    text.includes(
      "Mugiwara requires dynamic verification before it can generate and sea-trial an automated fix.",
    ),
    "fail-closed explanation shown verbatim",
  );

  // Human guidance for the suspected hardcoded secret — clearly advice, not a patch.
  assert.ok(text.includes("Rotate or revoke the exposed credential if it is real."), "rotation guidance");
  assert.ok(
    text.includes("Move secrets to environment variables or a secret-management configuration."),
    "secret-management guidance",
  );
  assert.ok(
    text.includes("guidance — not an automatically verified patch"),
    "guidance explicitly disclaimed as unverified",
  );

  // No fix affordance may exist, and nothing may reach /api/fix.
  assert.equal(document.querySelector(".js-fix-run"), null, "no Generate Fix button anywhere");
  assert.equal(document.querySelector(".panel .primary"), null, "no report-level fix button either");
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(fixCalls, 0, "/api/fix must not be called for a suspected-only report");

  // The suspected finding still shows its own status badge and no fabricated evidence.
  assert.ok(text.includes("SUSPECTED"));
  assert.ok(!text.includes("Canary token observed"));

  assertNoDomErrors(document);
  app.dom.window.close();
});

test("eligible finding shows Generate Fix; success bundle renders VERIFIED_FIXED with only a report reference sent", async () => {
  const envelope = reportEnvelope();
  const app = boot({
    hash: `#/findings/${REPORT_ID}`,
    routes: {
      "/api/reports": () => jsonResponse(200, { reports: [listingFor(envelope)] }),
      [`/api/reports/${REPORT_ID}`]: () => jsonResponse(200, envelope),
      "/api/fix": (_parsed, options) => {
        assert.equal(options.method, "POST");
        const body = JSON.parse(options.body);
        assert.deepEqual(
          Object.keys(body).sort(),
          ["report"],
          "the frontend may send ONLY the report reference — no findings/status overrides",
        );
        assert.equal(body.report, REPORT_ID);
        return Promise.resolve(jsonResponse(200, fixBundle([VERIFIED_FIXED_RECORD])));
      },
    },
  });
  const { document } = app;

  await expectRender(
    document,
    () => document.querySelector(".finding .js-fix-run"),
    "per-finding Generate Fix button rendered",
  );
  const btn = document.querySelector(".finding .js-fix-run");
  assert.equal(btn.textContent, "Generate Fix", "button labelled exactly 'Generate Fix'");
  assert.ok(btn.className.includes("primary"), "Generate Fix is prominent (primary)");
  assert.ok(document.body.textContent.includes("1"), "eligibility counts render"); // sanity

  btn.click();

  // Loading state is visible while the sea trial runs.
  await until(
    () => {
      const b = document.querySelector(".js-fix-run");
      return b && b.disabled && b.textContent === "Running sea trials…" ? b : null;
    },
    "disabled loading state 'Running sea trials…'",
  );

  await expectRender(
    document,
    () => [...document.querySelectorAll(".pill")].find((p) => p.textContent === "VERIFIED_FIXED"),
    "VERIFIED_FIXED pill rendered",
  );
  const results = document.body.textContent;
  assert.ok(results.includes("Threat Defeated"), "success flavor shown for VERIFIED_FIXED");
  assert.ok(results.includes("Canary token no longer observed"), "honest success checklist item");
  assert.ok(document.querySelector(".panel pre.diff"), "generated patch diff rendered");
  assert.ok(results.includes("Parameterized the query."), "patch explanation rendered");

  assert.equal(document.querySelector(".js-fix-run"), null, "fix buttons removed after success");
  assertNoDomErrors(document);
  app.dom.window.close();
});

test("NOT_FIXED and FAILED sea trials are displayed honestly and never as success", async () => {
  const envelope = reportEnvelope();
  const app = boot({
    hash: `#/findings/${REPORT_ID}`,
    routes: {
      "/api/reports": () => jsonResponse(200, { reports: [listingFor(envelope)] }),
      [`/api/reports/${REPORT_ID}`]: () => jsonResponse(200, envelope),
      "/api/fix": (_parsed, options) => {
        const body = JSON.parse(options.body);
        assert.deepEqual(Object.keys(body).sort(), ["report"], "only the report reference is sent");
        return Promise.resolve(jsonResponse(200, fixBundle([NOT_FIXED_RECORD, FAILED_RECORD])));
      },
    },
  });
  const { document } = app;

  const panelBtn = await expectRender(
    document,
    () =>
      [...document.querySelectorAll("button.js-fix-run")].find((b) =>
        b.textContent.startsWith("Generate Fix Bundle"),
      ),
    "report-level Generate Fix Bundle button rendered",
  );
  panelBtn.click();

  await expectRender(
    document,
    () => [...document.querySelectorAll(".pill")].filter((p) => p.textContent === "FAILED").length >= 1,
    "FAILED pill rendered",
  );
  const pills = [...document.querySelectorAll(".pill")].map((p) => p.textContent);
  assert.ok(pills.includes("NOT_FIXED"), "NOT_FIXED pill rendered");
  assert.ok(pills.includes("FAILED"), "FAILED pill rendered");
  assert.ok(!pills.includes("VERIFIED_FIXED"), "no VERIFIED_FIXED may be claimed");

  const text = document.body.textContent;
  assert.ok(text.includes("Patch Rejected"), "honest NOT_FIXED flavor");
  assert.ok(text.includes("Could Not Be Proven"), "honest FAILED flavor");
  assert.ok(
    text.includes("the canary token was observed after applying the patch."),
    "NOT_FIXED reason surfaced",
  );
  assert.ok(
    text.includes("inconclusive: rerun claimed exploitation but the canary token was never observed."),
    "inconclusive reason surfaced verbatim",
  );
  assert.ok(text.includes("The exploit could not be disproven after patching"), "failure checklist item");
  assert.ok(!text.includes("Threat Defeated"), "no success branding for failed trials");

  assertNoDomErrors(document);
  app.dom.window.close();
});
