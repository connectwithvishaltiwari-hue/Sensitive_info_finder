(function () {
  "use strict";
  const MAX = 100000;
  const $ = (id) => document.getElementById(id);
  const show = (el, on) => el.classList.toggle("hidden", !on);

  // Safe DOM builder: strings become text nodes, never HTML.
  function h(tag, props, ...kids) {
    const e = document.createElement(tag);
    if (props) for (const [k, v] of Object.entries(props)) {
      if (k === "class") e.className = v; else e.setAttribute(k, v);
    }
    for (const kid of kids.flat()) { if (kid != null) e.append(kid); }
    return e;
  }
  const td = (text, cls) => h("td", cls ? { class: cls } : null, String(text));
  const pct = (x) => (x == null ? "-" : (x * 100).toFixed(1) + "%");

  async function api(path, opts) {
    const res = await fetch(path, opts);
    let body = null;
    try { body = await res.json(); } catch (_) {}
    if (!res.ok) {
      let msg = "Request failed (" + res.status + ")";
      if (body && typeof body.detail === "string") msg = body.detail;
      else if (body && Array.isArray(body.detail)) msg = "Invalid input: " + body.detail.map((d) => d.msg).join("; ");
      throw new Error(msg);
    }
    return body;
  }
  const postJSON = (path, data, headers) => api(path, {
    method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, headers || {}),
    body: JSON.stringify(data) });

  // ---------- navigation ----------
  const loaders = { analytics: loadAnalytics, settings: loadSettings, playground: loadProvider };
  document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#nav button").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(".view").forEach((v) => show(v, v.id === "view-" + b.dataset.view));
    if (loaders[b.dataset.view]) loaders[b.dataset.view]();
  }));

  // Server offsets are Python code points; Array.from splits JS strings by code point.
  const sliceCp = (cps, s, e) => cps.slice(s, e).join("");

  // ---------- A. scanner ----------
  const scInput = $("sc-input");
  let lastSanitized = "";
  const updCounter = () => { $("sc-counter").textContent = Array.from(scInput.value).length + " / " + MAX; };
  scInput.addEventListener("input", updCounter);
  $("sc-clear").addEventListener("click", () => {
    scInput.value = ""; updCounter(); show($("sc-result"), false); show($("sc-error"), false); scInput.focus(); });
  $("sc-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(lastSanitized); $("sc-copied").textContent = "Copied!"; }
    catch (e) { $("sc-copied").textContent = "Copy failed - select the text manually."; }
    setTimeout(() => { $("sc-copied").textContent = ""; }, 2000);
  });

  function renderScan(text, data) {
    const cps = Array.from(text);
    const banner = $("sc-banner");
    show($("sc-result"), true);
    if (!data.has_sensitive) {
      banner.className = "banner ok";
      banner.replaceChildren("No sensitive data detected",
        h("small", null, "Nothing in this text matched the current detection rules."));
      show($("sc-details"), false);
      return;
    }
    const n = data.findings.length, o = data.policy.overall;
    banner.className = "banner " + (o === "BLOCK" ? "bad" : o === "WARN" ? "warn" : "bad");
    banner.replaceChildren(
      "Sensitive data detected: " + n + " item" + (n > 1 ? "s" : "") + " (risk: " + data.overall_risk + ")",
      h("small", null, "Policy decision: " + o + (data.policy.messages.length ? " - " + data.policy.messages.join(", ") : "")));
    show($("sc-details"), true);
    const rows = $("sc-rows"); rows.replaceChildren();
    data.findings.forEach((f) => {
      rows.append(h("tr", null,
        td(f.entity_type),
        h("td", null, h("code", { class: "val" }, sliceCp(cps, f.start, f.end))),
        td(f.start + "–" + f.end), td(Math.round(f.score * 100) + "%"),
        td(f.risk, "risk " + f.risk), td(f.action, "act " + f.action), td(f.detector)));
    });
    const hl = $("sc-highlight"); hl.replaceChildren();
    let pos = 0;
    data.findings.slice().sort((a, b) => a.start - b.start).forEach((f) => {
      if (f.start < pos) return;
      hl.append(sliceCp(cps, pos, f.start));
      hl.append(h("mark", { title: f.entity_type }, sliceCp(cps, f.start, f.end)));
      pos = f.end;
    });
    hl.append(sliceCp(cps, pos, cps.length));
    lastSanitized = data.sanitized_text;
    $("sc-sanitized").textContent = lastSanitized;
  }

  async function runScanner(promise, text) {
    show($("sc-error"), false);
    $("sc-scan").disabled = true;
    try { const data = await promise; renderScan(text !== null ? text : data.extracted_text, data); }
    catch (e) { $("sc-error").textContent = e.message || "Could not reach the server."; show($("sc-error"), true); show($("sc-result"), false); }
    finally { $("sc-scan").disabled = false; }
  }
  $("sc-scan").addEventListener("click", () => {
    const text = scInput.value;
    if (!text.trim()) { $("sc-error").textContent = "Please enter some text to scan."; show($("sc-error"), true); show($("sc-result"), false); return; }
    runScanner(postJSON("/api/scan", { text: text, mode: $("sc-mode").value, direction: $("sc-direction").value }), text);
  });
  scInput.addEventListener("keydown", (e) => { if (e.ctrlKey && e.key === "Enter") $("sc-scan").click(); });
  $("sc-file").addEventListener("change", (e) => {
    const f = e.target.files[0]; if (!f) return;
    const fd = new FormData(); fd.append("file", f); fd.append("mode", $("sc-mode").value);
    runScanner(api("/api/scan-file", { method: "POST", body: fd }).then((d) => { scInput.value = d.extracted_text; updCounter(); return d; }), null);
    e.target.value = "";
  });
  updCounter();

  // ---------- B. playground ----------
  async function loadProvider() {
    try {
      const s = await api("/api/settings");
      const b = $("pg-provider"); b.replaceChildren(
        h("span", { class: "badge " + (s.provider.is_mock ? "mock" : "real") },
          s.provider.is_mock ? "MOCK MODEL (offline, not a real LLM)" : "REAL PROVIDER: " + s.provider.name));
    } catch (_) {}
  }
  $("pg-send").addEventListener("click", async () => {
    const prompt = $("pg-input").value;
    show($("pg-error"), false);
    if (!prompt.trim()) { $("pg-error").textContent = "Please enter a prompt."; show($("pg-error"), true); return; }
    const btn = $("pg-send"); btn.disabled = true; btn.textContent = "Sending…";
    try {
      const r = await postJSON("/api/chat", { prompt: prompt, mode: $("pg-mode").value,
        confirm_warnings: $("pg-confirm").checked, restore_placeholders: $("pg-restore").checked });
      renderChat(prompt, r);
    } catch (e) { $("pg-error").textContent = e.message; show($("pg-error"), true); show($("pg-result"), false); }
    finally { btn.disabled = false; btn.textContent = "Send through gateway"; }
  });
  function renderChat(prompt, r) {
    const cps = Array.from(prompt);
    show($("pg-result"), true);
    const cls = r.status === "ok" ? (r.input_modified || r.output_modified ? "warn" : "ok")
              : r.status === "needs_confirmation" ? "warn" : "bad";
    const labels = { ok: "Completed", blocked: "Blocked - nothing was sent to the model",
      needs_confirmation: "Confirmation needed", response_blocked: "Response withheld",
      provider_error: "Provider error" };
    $("pg-banner").className = "banner " + cls;
    $("pg-banner").replaceChildren(labels[r.status] || r.status, h("small", null, r.message));
    const notes = $("pg-notes"); notes.replaceChildren();
    notes.append(h("li", null, "Model call made: " + (r.provider_called ? "yes" : "no") +
      " (" + (r.provider.is_mock ? "mock model" : r.provider.name) + ")"));
    if (r.input) r.input.messages.forEach((m) => notes.append(h("li", null, "Input policy: " + m)));
    if (r.output) r.output.messages.forEach((m) => notes.append(h("li", null, "Output policy: " + m)));
    const rows = $("pg-rows"); rows.replaceChildren();
    const fs = (r.input && r.input.findings) || [];
    show($("pg-findings-card"), fs.length > 0);
    fs.forEach((f) => rows.append(h("tr", null, td(f.entity_type),
      h("td", null, h("code", { class: "val" }, sliceCp(cps, f.start, f.end))),
      td(Math.round(f.score * 100) + "%"), td(f.action, "act " + f.action))));
    $("pg-sent").textContent = r.sent_to_model == null ? "(nothing sent)" : r.sent_to_model;
    $("pg-response").textContent = r.response == null ? "(no response shown)" : r.response;
    $("pg-outnote").textContent = r.output_modified ? "This response was modified by output scanning." : "";
  }

  // ---------- C. analytics ----------
  function bars(container, obj) {
    container.replaceChildren();
    const entries = Object.entries(obj), max = Math.max(1, ...entries.map((e) => e[1]));
    if (!entries.length) container.append(h("span", { class: "note" }, "none yet"));
    entries.forEach(([k, v]) => container.append(h("div", { class: "bar" },
      h("span", { class: "name" }, k), h("progress", { value: String(v), max: String(max) }), h("span", { class: "n" }, String(v)))));
  }
  async function loadAnalytics() {
    try {
      const s = await api("/api/stats");
      show($("an-empty"), s.total_scans === 0); show($("an-body"), s.total_scans > 0);
      if (s.total_scans > 0) {
        $("an-total").textContent = s.total_scans; $("an-last").textContent = s.last_scan || "-";
        bars($("an-entity"), s.by_entity); bars($("an-action"), s.by_action); bars($("an-source"), s.by_source);
      }
      const ev = await api("/api/evaluation");
      show($("ev-empty"), !ev.available); show($("ev-body"), ev.available);
      if (ev.available) renderEval(ev);
    } catch (e) { $("an-empty").textContent = e.message; show($("an-empty"), true); }
  }
  function renderEval(ev) {
    const d = ev.dataset;
    $("ev-meta").textContent = d.n_docs + " documents, " + d.n_entities + " labeled spans, seed " + d.seed +
      ". Positive: " + d.kinds.positive + ", benign: " + d.kinds.negative + ", hard negatives: " + d.kinds.hard_negative + ".";
    const rows = $("ev-rows"); rows.replaceChildren();
    const sel = $("ev-mode"); sel.replaceChildren();
    Object.entries(ev.modes).forEach(([m, r]) => {
      rows.append(h("tr", null, td(m), td(pct(r.strict.precision)), td(pct(r.strict.recall)), td(pct(r.strict.f1)),
        td(pct(r.fpr_benign)), td(pct(r.leakage_rate)), td(r.latency_ms.mean.toFixed(2)), td(r.latency_ms.p95.toFixed(2))));
      sel.append(h("option", { value: m }, m));
    });
    const draw = () => {
      const body = $("ev-cat"); body.replaceChildren();
      const r = ev.modes[sel.value];
      Object.entries(r.per_category).forEach(([c, v]) =>
        body.append(h("tr", null, td(c), td(v.support), td(pct(v.precision)), td(pct(v.recall)), td(pct(v.f1)))));
    };
    sel.onchange = draw; draw();
  }

  // ---------- D. settings ----------
  let entityMeta = [];
  async function loadSettings() {
    try {
      const [s, ents] = await Promise.all([api("/api/settings"), api("/api/entities")]);
      entityMeta = ents;
      const body = $("st-rows"); body.replaceChildren();
      ents.forEach((e) => {
        const sel = h("select", { "data-entity": e.entity },
          ...["ALLOW", "WARN", "MASK", "BLOCK"].map((a) => h("option", { value: a }, a)));
        sel.value = s.policy.entity_actions[e.entity] || s.policy.default_action;
        body.append(h("tr", null, td(e.entity), td(e.risk, "risk " + e.risk), td(e.support), h("td", null, sel), td(e.description)));
      });
      $("st-ignore").value = s.policy.ignore_below; $("st-warn").value = s.policy.warn_below;
      $("st-keywords").value = s.policy.custom_keywords.join("\n");
      $("st-restore").checked = s.policy.allow_placeholder_restoration;
      $("st-provider").textContent = "Active provider: " + s.provider.name + (s.provider.is_mock ? " (mock)" : "");
      $("st-provider-help").textContent = s.provider_help;
    } catch (e) { $("st-msg").textContent = e.message; }
  }
  $("st-verify").addEventListener("click", async () => {
    try { await api("/api/admin/check", { headers: { "X-API-Key": $("st-key").value } }); $("st-keystate").textContent = "Key accepted"; }
    catch (e) { $("st-keystate").textContent = "Key rejected"; }
  });
  $("st-save").addEventListener("click", async () => {
    const actions = {};
    document.querySelectorAll("#st-rows select").forEach((s) => { actions[s.dataset.entity] = s.value; });
    const payload = { entity_actions: actions, default_action: "MASK",
      ignore_below: parseFloat($("st-ignore").value), warn_below: parseFloat($("st-warn").value),
      custom_keywords: $("st-keywords").value.split("\n").map((x) => x.trim()).filter(Boolean),
      allow_placeholder_restoration: $("st-restore").checked };
    try {
      await api("/api/settings", { method: "PUT", headers: { "Content-Type": "application/json", "X-API-Key": $("st-key").value },
        body: JSON.stringify(payload) });
      $("st-msg").textContent = "Saved.";
    } catch (e) { $("st-msg").textContent = "Not saved: " + e.message; }
  });
})();
