/* veilweave desktop UI — framework-free, talks to Rust via window.__TAURI__. */
(function () {
  "use strict";

  const { invoke } = window.__TAURI__.core;
  const { listen } = window.__TAURI__.event;

  const TOKEN_URL = "https://dash.cloudflare.com/profile/api-tokens";
  const REPO_URL = "https://github.com/jacek4yang/veilweave";

  // ── state ─────────────────────────────────────────────────────────────
  const state = {
    lang: localStorage.getItem("vw-lang") ||
      ((navigator.language || "").toLowerCase().startsWith("zh") ? "zh" : "en"),
    page: "overview",
    config: null, // { accounts:[AccountView], deployments:[Deployment], ui_language }
    usage: {}, // name -> { loading, rows, analytics_error, free, ts }
    version: "",
    zones: {}, // account label -> active zones
    deploy: {
      sub: {
        account: "", worker_name: "", kv_title: "", kv_binding: "",
        endpoint: { mode: "workers-dev", primary: "workers-dev", custom_domain: null },
        settings: { max_nodes: 100, fingerprint: "chrome", ech: null },
      },
      relays: [],
      encryption: false,
      running: false,
      logs: [],
      done: null, // DeployDone
      started: false,
    },
  };

  // ── i18n ──────────────────────────────────────────────────────────────
  function t(key, vars) {
    let s = (window.I18N[state.lang] && window.I18N[state.lang][key]) ??
      window.I18N.en[key] ?? key;
    if (vars) for (const k in vars) s = s.replaceAll("{" + k + "}", vars[k]);
    return s;
  }

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function trunc(s, head = 10, tail = 6) {
    s = String(s ?? "");
    return s.length <= head + tail + 3 ? s : s.slice(0, head) + "…" + s.slice(-tail);
  }

  function fmtNum(n) { return Number(n).toLocaleString(state.lang === "zh" ? "zh-CN" : "en-US"); }

  // ── toasts ────────────────────────────────────────────────────────────
  function toast(msg, type = "info", ms = 4200) {
    const box = document.getElementById("toasts");
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => {
      el.classList.add("out");
      setTimeout(() => el.remove(), 220);
    }, ms);
  }

  // ── modal ─────────────────────────────────────────────────────────────
  function confirmModal({ title, body, confirmLabel, danger = true }) {
    return new Promise((resolve) => {
      const root = document.getElementById("modal-root");
      root.innerHTML = `
        <div class="modal-backdrop">
          <div class="modal ${danger ? "danger" : ""}">
            <h3>${esc(title)}</h3>
            <p>${body}</p>
            <div class="modal-actions">
              <button class="btn btn-ghost" data-act="cancel">${t("common.cancel")}</button>
              <button class="btn ${danger ? "btn-danger" : "btn-primary"}" data-act="ok">${esc(confirmLabel)}</button>
            </div>
          </div>
        </div>`;
      const close = (v) => { root.innerHTML = ""; resolve(v); };
      root.querySelector('[data-act="cancel"]').onclick = () => close(false);
      root.querySelector('[data-act="ok"]').onclick = () => close(true);
      root.querySelector(".modal-backdrop").addEventListener("mousedown", (e) => {
        if (e.target.classList.contains("modal-backdrop")) close(false);
      });
    });
  }

  // ── clipboard ─────────────────────────────────────────────────────────
  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    if (btn) {
      const old = btn.textContent;
      btn.textContent = t("common.copied");
      btn.classList.add("copied");
      setTimeout(() => { btn.textContent = old; btn.classList.remove("copied"); }, 1400);
    } else {
      toast(t("common.copied"), "success", 1600);
    }
  }

  function copyvalHtml(value, display) {
    return `<span class="copyval"><span title="${esc(value)}">${esc(display ?? value)}</span>` +
      `<button class="copy-btn" data-copy="${esc(value)}">${t("common.copy")}</button></span>`;
  }

  // wire all [data-copy] buttons in a container
  function wireCopy(container) {
    container.querySelectorAll("[data-copy]").forEach((b) => {
      b.onclick = (e) => { e.stopPropagation(); copyText(b.dataset.copy, b); };
    });
  }

  // ── backend glue ──────────────────────────────────────────────────────
  async function loadConfig() {
    state.config = await invoke("get_config");
  }

  async function refresh() {
    try { await loadConfig(); } catch (e) { toast(String(e), "error"); }
    renderPage();
  }

  // ── navigation ────────────────────────────────────────────────────────
  function setPage(page) {
    state.page = page;
    document.querySelectorAll(".nav-item").forEach((n) =>
      n.classList.toggle("active", n.dataset.nav === page));
    document.querySelectorAll(".page").forEach((p) =>
      p.classList.toggle("active", p.dataset.page === page));
    renderPage();
    if (page === "overview") refreshAllUsage();
  }

  function renderPage() {
    const el = document.querySelector(`.page[data-page="${state.page}"]`);
    if (!el) return;
    ({
      overview: renderOverview,
      accounts: renderAccounts,
      deploy: renderDeploy,
      manage: renderManage,
      settings: renderSettings,
    })[state.page](el);
    wireCopy(el);
  }

  function renderNavText() {
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    document.getElementById("lang-toggle").textContent = state.lang === "zh" ? "中 / EN" : "EN / 中";
  }

  // ── page: overview ────────────────────────────────────────────────────
  async function refreshAllUsage() {
    if (!state.config) return;
    for (const a of state.config.accounts) {
      const u = state.usage[a.name];
      if (u && u.loading) continue;
      state.usage[a.name] = { loading: true };
      renderUsageBlock(a.name);
      try {
        const r = await invoke("usage", { name: a.name });
        state.usage[a.name] = {
          loading: false, rows: r.rows,
          analytics_error: r.analytics_error,
          free: r.free_tier_daily_requests, ts: Date.now(),
        };
      } catch (e) {
        state.usage[a.name] = { loading: false, rows: [], analytics_error: String(e), free: 100000 };
      }
      renderUsageBlock(a.name);
    }
  }

  function renderUsageBlock(name) {
    const el = document.getElementById(`usage-${CSS.escape(name)}`);
    if (!el) return;
    const u = state.usage[name];
    if (!u || u.loading) {
      el.innerHTML = `
        <div class="skeleton" style="height:7px;margin:26px 0 10px"></div>
        <div class="skeleton" style="height:13px;width:60%"></div>`;
      return;
    }
    if (u.analytics_error) {
      el.innerHTML = `<div class="hint"><span>ⓘ</span><span>${t("ov.analyticsHint")}</span></div>`;
      return;
    }
    const total = u.rows.reduce((s, r) => s + r.requests, 0);
    const errors = u.rows.reduce((s, r) => s + r.errors, 0);
    const ratio = Math.min(1, total / u.free);
    const cls = ratio > 0.9 ? "danger" : ratio > 0.7 ? "warn" : "";
    const rows = u.rows.length ? `
      <table class="mini-table">
        <thead><tr><th>${t("ov.workers")}</th><th>${t("ov.requests")}</th><th>${t("ov.errors")}</th><th>${t("ov.cpu")}</th></tr></thead>
        <tbody>${u.rows.map((r) => `
          <tr><td>${esc(r.script)}</td><td>${fmtNum(r.requests)}</td>
          <td style="color:${r.errors ? "var(--red)" : "inherit"}">${fmtNum(r.errors)}</td>
          <td>${r.cpu_p50_us ? (r.cpu_p50_us / 1000).toFixed(2) + " ms" : "—"}</td></tr>`).join("")}
        </tbody>
      </table>` : `<div style="color:var(--muted);font-size:12.3px;margin-top:12px">${t("ov.noTraffic")}</div>`;
    el.innerHTML = `
      <div class="usage-nums"><span>${t("ov.today")}</span><span><b>${fmtNum(total)}</b> / ${fmtNum(u.free)} · ${fmtNum(errors)} ${t("ov.errors")}</span></div>
      <div class="meter ${cls}"><i style="width:${Math.max(1, ratio * 100)}%"></i></div>
      ${rows}`;
  }

  function renderOverview(el) {
    const cfg = state.config;
    const cards = cfg && cfg.accounts.length ? `<div class="acct-grid">` + cfg.accounts.map((a) => `
      <div class="card acct-card">
        <div class="acct-head">
          <h3>${esc(a.name)}</h3>
          <span style="color:var(--muted);font-size:12px">${t("ov.deploys", { n: a.deployment_count })}</span>
        </div>
        <div class="acct-meta">
          <div class="row"><span class="k">${t("ov.accountId")}</span>${copyvalHtml(a.account_id, trunc(a.account_id, 12, 8))}</div>
          <div class="row"><span class="k">${t("ov.subdomain")}</span><span class="mono" style="color:var(--text-2)">${esc(a.workers_dev_subdomain || "—")}.workers.dev</span></div>
        </div>
        <div id="usage-${esc(a.name)}"></div>
      </div>`).join("") + `</div>`
      : `<div class="empty">
          <div class="empty-icon">☁️</div>
          <h4>${t("ov.empty.title")}</h4>
          <p>${t("ov.empty.desc")}</p>
          <button class="btn btn-primary" data-goto="accounts">${t("ov.empty.cta")}</button>
        </div>`;

    el.innerHTML = `
      <div class="page-head">
        <div><h1>${t("ov.title")}</h1><div class="sub">${t("ov.sub")}</div></div>
        <button class="btn btn-ghost" id="ov-refresh">⟳ ${t("common.refresh")}</button>
      </div>
      ${cards}`;

    el.querySelector("#ov-refresh").onclick = () => { state.usage = {}; refreshAllUsage(); };
    el.querySelectorAll("[data-goto]").forEach((b) => (b.onclick = () => setPage(b.dataset.goto)));
    if (cfg) cfg.accounts.forEach((a) => renderUsageBlock(a.name));
  }

  // ── page: accounts ────────────────────────────────────────────────────
  function renderAccounts(el) {
    const cfg = state.config;
    const rows = cfg && cfg.accounts.length ? cfg.accounts.map((a) => `
      <tr>
        <td style="font-weight:600">${esc(a.name)}</td>
        <td>${copyvalHtml(a.account_id, trunc(a.account_id, 10, 6))}</td>
        <td class="mono" style="color:var(--text-2)">${esc(a.workers_dev_subdomain || "—")}</td>
        <td>${a.deployment_count}</td>
        <td><div class="deploy-row-actions">
          <button class="btn btn-ghost btn-sm" data-usage="${esc(a.name)}">${t("ac.usage")}</button>
          <button class="btn btn-ghost btn-sm" data-recover="${esc(a.name)}">${t("ac.recover")}</button>
          <button class="btn btn-danger btn-sm" data-del-acct="${esc(a.name)}"
            ${a.deployment_count ? `disabled title="${t("ac.delete.blocked")}"` : ""}>${t("common.delete")}</button>
        </div></td>
      </tr>`).join("")
      : `<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:26px">${t("ov.empty.desc")}</td></tr>`;

    el.innerHTML = `
      <div class="page-head"><div><h1>${t("ac.title")}</h1><div class="sub">${t("ac.sub")}</div></div></div>

      <div class="card">
        <h2 class="card-title">${t("ac.add.title")}</h2>
        <p class="card-desc">${t("ac.add.desc")}</p>
        <div style="display:flex;flex-wrap:wrap;gap:7px;margin-bottom:16px">
          ${[1, 2, 3, 4, 5, 6].map((i) => `<span class="chip" style="background:rgba(99,102,241,.1);color:var(--text-2);border:1px solid rgba(99,102,241,.25)">${t("ac.perm." + i)}</span>`).join("")}
        </div>
        <div class="field">
          <button class="btn btn-ghost btn-sm" id="open-token-url">↗ ${t("ac.tokenPage")}</button>
          <div class="mt8">${copyvalHtml(TOKEN_URL)}</div>
        </div>
        <div class="grid-2">
          <div class="field">
            <label class="field-label">${t("ac.label")}</label>
            <input type="text" id="add-label" placeholder="${t("ac.label.ph")}" />
          </div>
          <div class="field">
            <label class="field-label">${t("ac.token")}</label>
            <input type="password" id="add-token" class="mono" placeholder="${t("ac.token.ph")}" autocomplete="off" />
          </div>
        </div>
        <div id="account-picker"></div>
        <button class="btn btn-primary" id="add-account">${t("ac.verify")}</button>
      </div>

      <div class="card">
        <h2 class="card-title">${t("ac.list.title")}</h2>
        <table class="table mt12">
          <thead><tr>
            <th>${t("ac.col.name")}</th><th>${t("ac.col.id")}</th>
            <th>${t("ac.col.sub")}</th><th>${t("ac.col.deploys")}</th><th style="text-align:right">${t("ac.col.actions")}</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;

    el.querySelector("#open-token-url").onclick = () => invoke("open_url", { url: TOKEN_URL });

    el.querySelector("#add-account").onclick = async (e) => {
      const btn = e.currentTarget;
      const label = el.querySelector("#add-label").value.trim();
      const token = el.querySelector("#add-token").value.trim();
      if (!token) { toast(t("ac.token.ph"), "error"); return; }
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner"></span> ${t("common.loading")}`;
      try {
        let accountId = el.querySelector("#account-choice")?.value || null;
        if (!accountId) {
          const candidates = await invoke("discover_accounts", { token });
          if (candidates.length > 1) {
            el.querySelector("#account-picker").innerHTML = `<div class="field">
              <label class="field-label">${t("ac.chooseAccount")}</label>
              <select id="account-choice">${candidates.map((a) =>
                `<option value="${esc(a.account_id)}">${esc(a.name)} · ${esc(a.account_id)}</option>`).join("")}</select>
            </div>`;
            btn.disabled = false;
            btn.textContent = t("ac.addSelected");
            return;
          }
          accountId = candidates[0]?.account_id || null;
        }
        const acc = await invoke("add_account", { label: label || null, token, accountId });
        el.querySelector("#add-token").value = "";
        toast(t("ac.added", { name: acc.name }), "success");
        await refresh();
      } catch (err) {
        toast(String(err), "error", 7000);
        btn.disabled = false;
        btn.textContent = t("ac.verify");
      }
    };

    el.querySelectorAll("[data-usage]").forEach((b) => (b.onclick = () => setPage("overview")));
    el.querySelectorAll("[data-recover]").forEach((b) => (b.onclick = async () => {
      const name = b.dataset.recover;
      b.disabled = true;
      b.innerHTML = `<span class="spinner dark"></span>`;
      try {
        const r = await invoke("recover", { name });
        toast(r.added ? t("ac.recovered", { n: r.added }) : t("ac.recovered.none"), r.added ? "success" : "info");
        (r.summary || []).slice(0, 6).forEach((s) => toast(s, "info", 6000));
        await refresh();
      } catch (err) {
        toast(String(err), "error", 7000);
        b.disabled = false;
        b.textContent = t("ac.recover");
      }
    }));
    el.querySelectorAll("[data-del-acct]").forEach((b) => (b.onclick = async () => {
      const name = b.dataset.delAcct;
      const ok = await confirmModal({
        title: t("ac.delete.title"),
        body: esc(t("ac.delete.body", { name })),
        confirmLabel: t("common.delete"),
      });
      if (!ok) return;
      try {
        await invoke("delete_account", { name });
        toast(t("ac.deleted", { name }), "success");
        await refresh();
      } catch (err) { toast(String(err), "error", 7000); }
    }));
  }

  // ── page: deploy ──────────────────────────────────────────────────────
  const NAME_RE = /^[a-z0-9-]{1,63}$/;

  function defaultEndpoint() {
    return { mode: "workers-dev", primary: "workers-dev", custom_domain: null };
  }

  function endpointEditor(endpoint, account, cls = "") {
    endpoint = endpoint || defaultEndpoint();
    const custom = endpoint.mode !== "workers-dev";
    const domain = endpoint.custom_domain || { hostname: "", zone_id: "", zone_name: "" };
    const zones = state.zones[account] || [];
    const zoneOptions = zones.map((zone) =>
      `<option value="${esc(zone.id)}" data-name="${esc(zone.name)}" ${zone.id === domain.zone_id ? "selected" : ""}>${esc(zone.name)}</option>`).join("");
    const primaryOptions = endpoint.mode === "both"
      ? `<option value="workers-dev" ${endpoint.primary === "workers-dev" ? "selected" : ""}>workers.dev</option><option value="custom-domain" ${endpoint.primary === "custom-domain" ? "selected" : ""}>${t("dp.endpoint.custom")}</option>`
      : `<option value="${endpoint.mode === "custom-domain" ? "custom-domain" : "workers-dev"}">${endpoint.mode === "custom-domain" ? t("dp.endpoint.custom") : "workers.dev"}</option>`;
    return `<div class="endpoint-editor ${cls}">
      <div class="field"><label class="field-label">${t("dp.endpoint.mode")}</label>
        <select class="ep-mode"><option value="workers-dev" ${endpoint.mode === "workers-dev" ? "selected" : ""}>${t("dp.endpoint.workers")}</option><option value="custom-domain" ${endpoint.mode === "custom-domain" ? "selected" : ""}>${t("dp.endpoint.customOnly")}</option><option value="both" ${endpoint.mode === "both" ? "selected" : ""}>${t("dp.endpoint.both")}</option></select></div>
      <div class="field"><label class="field-label">${t("dp.endpoint.primary")}</label><select class="ep-primary">${primaryOptions}</select></div>
      <div class="field ${custom ? "" : "endpoint-disabled"}"><label class="field-label">${t("dp.endpoint.zone")}</label>
        <div class="field-row"><div class="grow"><select class="ep-zone" ${custom ? "" : "disabled"}><option value="">${t("dp.endpoint.chooseZone")}</option>${zoneOptions}</select></div><button type="button" class="btn btn-ghost btn-sm ep-load-zones" ${custom ? "" : "disabled"}>${t("dp.endpoint.loadZones")}</button></div></div>
      <div class="field ${custom ? "" : "endpoint-disabled"}"><label class="field-label">${t("dp.endpoint.hostname")}</label><input class="ep-host mono" value="${esc(domain.hostname)}" ${custom ? "" : "disabled"} placeholder="sub.example.com" /></div>
      ${custom && domain.hostname ? `<div class="endpoint-preview">https://${esc(domain.hostname)}</div>` : ""}
    </div>`;
  }

  function readEndpoint(editor, existing) {
    if (!editor) return existing || defaultEndpoint();
    const mode = editor.querySelector(".ep-mode").value;
    const primary = editor.querySelector(".ep-primary").value;
    if (mode === "workers-dev") return { mode, primary: "workers-dev", custom_domain: null };
    const zone = editor.querySelector(".ep-zone");
    const option = zone.options[zone.selectedIndex];
    return {
      mode, primary,
      custom_domain: {
        hostname: editor.querySelector(".ep-host").value.trim(),
        zone_id: zone.value,
        zone_name: option?.dataset.name || option?.textContent || "",
      },
    };
  }

  async function loadZones(account, el) {
    try {
      state.zones[account] = await invoke("list_zones", { name: account });
      readDeployForm(el);
      renderDeploy(el);
    } catch (err) { toast(String(err), "error", 7000); }
  }

  function readDeployForm(el) {
    const d = state.deploy;
    d.sub.account = el.querySelector("#dp-sub-account")?.value ?? d.sub.account;
    d.sub.worker_name = el.querySelector("#dp-sub-name")?.value ?? d.sub.worker_name;
    d.sub.kv_title = el.querySelector("#dp-kv-title")?.value ?? d.sub.kv_title;
    d.sub.kv_binding = el.querySelector("#dp-kv-binding")?.value ?? d.sub.kv_binding;
    d.sub.endpoint = readEndpoint(el.querySelector(".sub-endpoint"), d.sub.endpoint);
    d.sub.settings = {
      max_nodes: Number(el.querySelector("#dp-max-nodes")?.value || d.sub.settings?.max_nodes || 100),
      fingerprint: el.querySelector("#dp-fingerprint")?.value || d.sub.settings?.fingerprint || "chrome",
      ech: el.querySelector("#dp-ech")?.value.trim() || null,
    };
    d.encryption = el.querySelector("#dp-encryption")?.checked ?? d.encryption;
    el.querySelectorAll(".relay-row").forEach((row) => {
      const i = Number(row.dataset.idx);
      if (d.relays[i]) {
        d.relays[i].account = row.querySelector(".rl-account").value;
        d.relays[i].worker_name = row.querySelector(".rl-name").value;
        d.relays[i].endpoint = readEndpoint(row.querySelector(".relay-endpoint"), d.relays[i].endpoint);
      }
    });
  }

  function accountOptions(selected) {
    const cfg = state.config;
    if (!cfg) return "";
    return cfg.accounts.map((a) =>
      `<option value="${esc(a.name)}" ${a.name === selected ? "selected" : ""}>${esc(a.name)}</option>`).join("");
  }

  async function fillRandom(inputEl, what) {
    inputEl.value = await invoke(what === "kv" ? "random_kv_binding" : "random_worker_name");
    inputEl.dispatchEvent(new Event("input"));
  }

  function renderDeploy(el) {
    const d = state.deploy;
    const cfg = state.config;
    const noAccounts = !cfg || cfg.accounts.length === 0;
    if (!d.relays.length && cfg && cfg.accounts.length) {
      d.relays.push({ account: cfg.accounts[0].name, worker_name: "", endpoint: defaultEndpoint() });
      d.sub.account = d.sub.account || cfg.accounts[0].name;
    }

    if (d.started) { renderDeployRun(el); return; }

    const relayRows = d.relays.map((r, i) => `
      <div class="relay-row" data-idx="${i}">
        <div style="display:flex;align-items:center"><span class="idx">${i + 1}</span>
          <select class="rl-account" style="flex:1">${accountOptions(r.account)}</select></div>
        <input type="text" class="rl-name mono" placeholder="${t("dp.workerName")}" value="${esc(r.worker_name)}" />
        <button class="btn btn-ghost btn-sm rl-random">${t("common.random")}</button>
        <button class="icon-btn danger rl-remove" title="${t("common.delete")}" ${d.relays.length <= 1 ? "disabled style=opacity:.3" : ""}>✕</button>
        ${endpointEditor(r.endpoint, r.account, "relay-endpoint")}
      </div>`).join("");

    const validCount = d.relays.filter((r) => NAME_RE.test(r.worker_name)).length;
    const summary = !d.relays.length
      ? t("dp.summary.none")
      : t("dp.summary", {
          sub: d.sub.worker_name || "…",
          subAcct: `<b>${esc(d.sub.account)}</b>`,
          n: d.relays.length,
        });

    el.innerHTML = `
      <div class="page-head"><div><h1>${t("dp.title")}</h1><div class="sub">${t("dp.sub")}</div></div></div>
      ${noAccounts ? `<div class="empty"><div class="empty-icon">🔑</div><h4>${t("ov.empty.title")}</h4>
        <p>${t("dp.needAccount")}</p><button class="btn btn-primary" data-goto="accounts">${t("ov.empty.cta")}</button></div>` : `

      <div class="card">
        <div class="section-label">${t("dp.section.sub")}</div>
        <div class="grid-2">
          <div class="field">
            <label class="field-label">${t("dp.account")}</label>
            <select id="dp-sub-account">${accountOptions(d.sub.account)}</select>
          </div>
          <div class="field">
            <label class="field-label">${t("dp.workerName")}</label>
            <div class="field-row">
              <div class="grow"><input type="text" id="dp-sub-name" class="mono" value="${esc(d.sub.worker_name)}" placeholder="hub-service-xxxx" /></div>
              <button class="btn btn-ghost btn-sm" id="dp-sub-random">${t("common.random")}</button>
            </div>
            <div class="field-err" id="err-sub-name"></div>
          </div>
          <div class="field">
            <label class="field-label">${t("dp.kvTitle")}</label>
            <input type="text" id="dp-kv-title" class="mono" value="${esc(d.sub.kv_title)}" placeholder="(worker-name)-kv" />
          </div>
          <div class="field">
            <label class="field-label">${t("dp.kvBinding")}</label>
            <div class="field-row">
              <div class="grow"><input type="text" id="dp-kv-binding" class="mono" value="${esc(d.sub.kv_binding)}" placeholder="kv_xxxxxx" /></div>
              <button class="btn btn-ghost btn-sm" id="dp-kv-random">${t("common.random")}</button>
            </div>
          </div>
        </div>
        <hr class="divider" />
        <div class="section-label">${t("dp.endpoint.title")}</div>
        ${endpointEditor(d.sub.endpoint, d.sub.account, "sub-endpoint")}
        <hr class="divider" />
        <div class="section-label">${t("dp.advanced")}</div>
        <div class="grid-2">
          <div class="field"><label class="field-label">MAX_NODES</label><input id="dp-max-nodes" type="number" min="1" max="1000" value="${esc(d.sub.settings?.max_nodes || 100)}" /></div>
          <div class="field"><label class="field-label">FP</label><select id="dp-fingerprint">${["chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"].map((fp) => `<option value="${fp}" ${fp === (d.sub.settings?.fingerprint || "chrome") ? "selected" : ""}>${fp}</option>`).join("")}</select></div>
          <div class="field"><label class="field-label">ECH</label><input id="dp-ech" value="${esc(d.sub.settings?.ech || "")}" placeholder="${t("dp.echPlaceholder")}" /></div>
        </div>
      </div>

      <div class="card">
        <div class="section-label">${t("dp.section.relays")}</div>
        <div id="relay-list">${relayRows}</div>
        <button class="btn btn-ghost btn-sm mt8" id="dp-add-relay">＋ ${t("dp.addRelay")}</button>

        <hr class="divider" />
        <label class="check-row">
          <input type="checkbox" id="dp-encryption" ${d.encryption ? "checked" : ""} />
          <span>${t("dp.encryption")} <span class="chip chip-exp">${t("dp.encryption.chip")}</span></span>
        </label>
        <div id="enc-warn" class="hint mt12" style="display:${d.encryption ? "flex" : "none"}"><span>⚠</span><span>${t("dp.encryption.warn")}</span></div>
      </div>

      <div class="card">
        <div class="plan-summary">${summary}</div>
        <button class="btn btn-primary btn-block mt16" id="dp-start" ${validCount === 0 ? "disabled" : ""}>${t("dp.start")}</button>
      </div>`}`;

    if (noAccounts) {
      el.querySelectorAll("[data-goto]").forEach((b) => (b.onclick = () => setPage(b.dataset.goto)));
      return;
    }

    const rerender = () => { readDeployForm(el); renderDeploy(el); };

    el.querySelector("#dp-sub-random").onclick = async (e) => {
      e.preventDefault();
      await fillRandom(el.querySelector("#dp-sub-name"));
      const n = el.querySelector("#dp-sub-name");
      const kv = el.querySelector("#dp-kv-title");
      if (!kv.value) kv.value = n.value + "-kv";
      readDeployForm(el); renderDeploy(el);
    };
    el.querySelector("#dp-kv-random").onclick = async (e) => {
      e.preventDefault();
      await fillRandom(el.querySelector("#dp-kv-binding"), "kv");
      readDeployForm(el); renderDeploy(el);
    };
    el.querySelector("#dp-sub-name").addEventListener("input", (e) => {
      const ok = NAME_RE.test(e.target.value) || e.target.value === "";
      e.target.classList.toggle("invalid", !ok);
      el.querySelector("#err-sub-name").textContent = ok ? "" : t("dp.invalidName");
      readDeployForm(el); updateDeployStartBtn(el);
    });
    ["#dp-sub-account", "#dp-kv-title", "#dp-kv-binding", "#dp-max-nodes", "#dp-fingerprint", "#dp-ech"].forEach((sel) =>
      el.querySelector(sel).addEventListener("input", () => { readDeployForm(el); updateSummary(el); }));
    el.querySelector("#dp-encryption").addEventListener("change", (e) => {
      readDeployForm(el);
      el.querySelector("#enc-warn").style.display = e.target.checked ? "flex" : "none";
    });

    el.querySelectorAll(".relay-row").forEach((row) => {
      row.querySelector(".rl-random").onclick = async (e) => {
        e.preventDefault();
        await fillRandom(row.querySelector(".rl-name"));
        readDeployForm(el); renderDeploy(el);
      };
      row.querySelector(".rl-name").addEventListener("input", (e) => {
        const ok = NAME_RE.test(e.target.value) || e.target.value === "";
        e.target.classList.toggle("invalid", !ok);
        readDeployForm(el); updateDeployStartBtn(el);
      });
      row.querySelector(".rl-account").addEventListener("change", () => { readDeployForm(el); updateSummary(el); });
      row.querySelector(".rl-remove").onclick = () => {
        readDeployForm(el);
        state.deploy.relays.splice(Number(row.dataset.idx), 1);
        renderDeploy(el);
      };
    });
    el.querySelector("#dp-add-relay").onclick = () => {
      readDeployForm(el);
      state.deploy.relays.push({ account: state.config.accounts[0].name, worker_name: "", endpoint: defaultEndpoint() });
      renderDeploy(el);
    };
    el.querySelectorAll(".ep-mode, .ep-primary").forEach((input) => input.addEventListener("change", rerender));
    el.querySelectorAll(".ep-zone, .ep-host").forEach((input) => input.addEventListener("input", () => readDeployForm(el)));
    el.querySelectorAll(".ep-load-zones").forEach((button) => button.onclick = async () => {
      const row = button.closest(".relay-row");
      const account = row ? row.querySelector(".rl-account").value : el.querySelector("#dp-sub-account").value;
      await loadZones(account, el);
    });
    el.querySelector("#dp-start").onclick = () => startDeploy(el);
  }

  function updateSummary(el) {
    const d = state.deploy;
    const box = el.querySelector(".plan-summary");
    if (box) box.innerHTML = t("dp.summary", {
      sub: d.sub.worker_name || "…", subAcct: `<b>${esc(d.sub.account)}</b>`, n: d.relays.length,
    });
  }

  function updateDeployStartBtn(el) {
    const d = state.deploy;
    const ok = NAME_RE.test(d.sub.worker_name) && d.relays.length > 0 &&
      d.relays.every((r) => NAME_RE.test(r.worker_name)) && d.sub.kv_binding;
    const btn = el.querySelector("#dp-start");
    if (btn) btn.disabled = !ok;
  }

  async function startDeploy(el) {
    readDeployForm(el);
    const d = state.deploy;
    const namesOk = NAME_RE.test(d.sub.worker_name) && d.relays.every((r) => NAME_RE.test(r.worker_name));
    if (!namesOk || !d.relays.length) { toast(t("dp.invalidName"), "error"); return; }
    if (!d.sub.kv_title) d.sub.kv_title = d.sub.worker_name + "-kv";
    if (!d.sub.kv_binding) d.sub.kv_binding = await invoke("random_kv_binding");

    d.running = true;
    d.started = true;
    d.logs = [];
    d.done = null;
    renderDeployRun(document.querySelector('.page[data-page="deploy"]'));
    try {
      await invoke("start_deploy", {
        plan: {
          sub: { ...d.sub },
          relays: d.relays.map((r) => ({ ...r })),
          encryption: d.encryption,
        },
      });
    } catch (err) {
      d.running = false;
      toast(String(err), "error", 7000);
      renderDeployRun(document.querySelector('.page[data-page="deploy"]'));
    }
  }

  function renderDeployRun(el) {
    if (!el) return;
    const d = state.deploy;
    const status = d.running
      ? `<span style="display:inline-flex;align-items:center;gap:8px;color:var(--accent-2)"><span class="spinner dark"></span>${t("dp.running")}</span>`
      : d.done && d.done.ok
        ? `<span style="color:var(--green)">✓ ${t("dp.success")}</span>`
        : `<span style="color:var(--red)">✕ ${t("dp.failed")}</span>`;

    el.innerHTML = `
      <div class="page-head"><div><h1>${t("dp.title")}</h1><div class="sub">${t("dp.sub")}</div></div>${status}</div>
      <div class="card">
        <h2 class="card-title">${t("dp.log.title")}</h2>
        <div class="log-console" id="deploy-log"></div>
      </div>
      <div id="deploy-result"></div>
      <div class="mt16">
        <button class="btn btn-ghost" id="dp-back" ${d.running ? "disabled" : ""}>← ${t("dp.title")}</button>
      </div>`;

    paintLogs(el);
    if (d.done) paintDeployResult(el);
    el.querySelector("#dp-back").onclick = () => {
      state.deploy.started = false;
      state.deploy.done = null;
      refresh();
    };
  }

  function paintLogs(el) {
    const box = el.querySelector("#deploy-log");
    if (!box) return;
    box.innerHTML = state.deploy.logs.map((l) =>
      `<div class="log-line log-${l.kind}"><span class="tag">${l.kind}</span><span class="msg">${esc(l.message)}</span></div>`).join("");
    box.scrollTop = box.scrollHeight;
  }

  function paintDeployResult(el) {
    const d = state.deploy;
    const box = el.querySelector("#deploy-result");
    if (!box || !d.done) return;
    if (d.done.ok) {
      box.innerHTML = `
        <div class="success-card mt16">
          <div class="big-check">✓</div>
          <h3 style="margin:0 0 6px">${t("dp.success")}</h3>
          <p style="color:var(--text-2);margin:0">${t("dp.success.desc")}</p>
          ${d.done.sub_deployment_id ? `<button class="btn btn-primary mt16" data-fetch-sub="${esc(d.done.sub_deployment_id)}">${t("mg.copySub")}</button>` : ""}
          <div style="color:var(--muted);font-size:12px">${d.done.completed.map(esc).join(" · ")}</div>
        </div>`;
      box.querySelector("[data-fetch-sub]")?.addEventListener("click", async (event) => {
        try {
          const url = await invoke("get_subscription_url", { deploymentId: event.currentTarget.dataset.fetchSub });
          await copyText(url, event.currentTarget);
        } catch (err) { toast(String(err), "error", 7000); }
      });
    } else if (!d.done.ok) {
      box.innerHTML = `<div class="hint mt16" style="border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.07);color:var(--red)">
        <span>✕</span><span class="mono" style="font-size:12px">${esc(d.done.error || "")}</span></div>`;
    }
  }

  // ── page: manage ──────────────────────────────────────────────────────
  function renderManage(el) {
    const cfg = state.config;
    let body;
    if (!cfg || cfg.deployments.length === 0) {
      body = `<div class="empty"><div class="empty-icon">🛰️</div>
        <h4>${t("mg.empty.title")}</h4><p>${t("mg.empty.desc")}</p></div>`;
    } else {
      const groups = {};
      for (const dep of cfg.deployments) (groups[dep.account] ||= []).push(dep);
      body = Object.entries(groups).map(([acct, deps]) => `
        <div class="acct-group-head"><h3>${esc(acct)}</h3><span class="count">${deps.length}</span></div>
        <div class="card" style="padding:6px 10px">
          <table class="table manage-table">
            <thead><tr>
              <th>${t("mg.col.role")}</th><th>${t("mg.col.name")}</th><th>${t("mg.col.domain")}</th>
              <th>${t("mg.col.created")}</th><th style="text-align:right">${t("mg.col.actions")}</th>
            </tr></thead>
            <tbody>${deps.map((d) => {
              return `<tr>
                <td><span class="badge badge-${d.role}">${t("mg.role." + d.role)}</span></td>
                <td class="mono" style="font-weight:600" title="${esc(d.name)}">${esc(d.name)}</td>
                <td>${d.domain ? copyvalHtml("https://" + d.domain, trunc(d.domain, 13, 7)) : "—"}</td>
                <td style="color:var(--muted);font-size:12.3px">${esc((d.created_at || "").slice(0, 10))}</td>
                <td><div class="deploy-row-actions">
                  ${d.sub ? `<button class="btn btn-ghost btn-sm" data-fetch-sub="${esc(d.id)}">${t("mg.copySub")}</button>` : ""}
                  ${d.sub ? `<button class="btn btn-ghost btn-sm" data-rotate-token="${esc(d.id)}">${t("mg.rotateToken")}</button>` : ""}
                  ${d.sub ? `<button class="btn btn-ghost btn-sm" data-proxyip-status="${esc(d.id)}">${t("mg.proxyip.status")}</button>` : ""}
                  ${d.sub ? `<button class="btn btn-ghost btn-sm" data-proxyip-refresh="${esc(d.id)}">${t("mg.proxyip.refresh")}</button>` : ""}
                  ${d.previous_version_id ? `<button class="btn btn-ghost btn-sm" data-rollback="${esc(d.id)}">${t("mg.rollback")}</button>` : ""}
                  <button class="btn btn-ghost btn-sm" data-update="${esc(d.account)}|${esc(d.name)}">${t("mg.update")}</button>
                  <button class="btn btn-danger btn-sm" data-del-dep="${esc(d.account)}|${esc(d.name)}">${t("common.delete")}</button>
                </div></td>
              </tr>`;
            }).join("")}</tbody>
          </table>
        </div>`).join("");
    }

    el.innerHTML = `
      <div class="page-head"><div><h1>${t("mg.title")}</h1><div class="sub">${t("mg.sub")}</div></div>
        <button class="btn btn-ghost" id="mg-refresh">⟳ ${t("common.refresh")}</button></div>
      ${body}`;

    el.querySelector("#mg-refresh").onclick = refresh;

    el.querySelectorAll("[data-fetch-sub]").forEach((b) => (b.onclick = async () => {
      try {
        const url = await invoke("get_subscription_url", { deploymentId: b.dataset.fetchSub });
        await copyText(url, b);
      } catch (err) { toast(String(err), "error", 7000); }
    }));

    el.querySelectorAll("[data-rollback]").forEach((b) => (b.onclick = async () => {
      const ok = await confirmModal({
        title: t("mg.rollback"), body: esc(t("mg.rollback.confirm")),
        confirmLabel: t("mg.rollback"), danger: false,
      });
      if (!ok) return;
      try {
        await invoke("rollback_deployment", { deploymentId: b.dataset.rollback });
        toast(t("mg.rolledBack"), "success");
        await refresh();
      } catch (err) { toast(String(err), "error", 7000); }
    }));

    el.querySelectorAll("[data-rotate-token]").forEach((b) => (b.onclick = async () => {
      const ok = await confirmModal({
        title: t("mg.rotateToken"), body: esc(t("mg.rotateToken.confirm")),
        confirmLabel: t("mg.rotateToken"), danger: true,
      });
      if (!ok) return;
      b.disabled = true;
      try {
        await invoke("rotate_subscription_token", { deploymentId: b.dataset.rotateToken });
        toast(t("mg.tokenRotated"), "success");
        await refresh();
      } catch (err) { toast(String(err), "error", 7000); b.disabled = false; }
    }));

    el.querySelectorAll("[data-proxyip-status]").forEach((b) => (b.onclick = async () => {
      b.disabled = true;
      try {
        const status = await invoke("get_proxyip_cache_status", { deploymentId: b.dataset.proxyipStatus });
        const ageMinutes = status.age_ms == null ? "?" : Math.floor(status.age_ms / 60000);
        toast(t("mg.proxyip.summary", {
          state: status.stale ? t("mg.proxyip.stale") : status.validation,
          age: ageMinutes,
          count: status.stored_count || 0,
          countries: status.country_count || 0,
        }), status.validation === "valid" ? "success" : "error", 7000);
      } catch (err) { toast(String(err), "error", 7000); }
      finally { b.disabled = false; }
    }));

    el.querySelectorAll("[data-proxyip-refresh]").forEach((b) => (b.onclick = async () => {
      b.disabled = true;
      try {
        const report = await invoke("refresh_proxyip_cache", { deploymentId: b.dataset.proxyipRefresh });
        toast(t("mg.proxyip.refreshed", {
          count: report.stored_count,
          countries: report.country_count,
        }), "success", 7000);
      } catch (err) { toast(String(err), "error", 7000); }
      finally { b.disabled = false; }
    }));

    el.querySelectorAll("[data-update]").forEach((b) => (b.onclick = async () => {
      const [account, name] = b.dataset.update.split("|");
      b.disabled = true;
      b.innerHTML = `<span class="spinner dark"></span>`;
      try {
        await invoke("update_deployment", { name, account });
        toast(t("mg.updated", { name }), "success");
      } catch (err) { toast(String(err), "error", 7000); }
      b.disabled = false;
      b.textContent = t("mg.update");
    }));

    el.querySelectorAll("[data-del-dep]").forEach((b) => (b.onclick = async () => {
      const [account, name] = b.dataset.delDep.split("|");
      const dep = state.config.deployments.find((x) => x.account === account && x.name === name);
      const ok = await confirmModal({
        title: t("mg.delete.title"),
        body: esc(t(dep && dep.role === "sub" ? "mg.delete.body.sub" : "mg.delete.body.relay", { name })),
        confirmLabel: t("common.delete"),
      });
      if (!ok) return;
      try {
        await invoke("delete_deployment", { name, account });
        toast(t("mg.deleted", { name }), "success");
        await refresh();
      } catch (err) { toast(String(err), "error", 7000); }
    }));
  }

  // ── page: settings ────────────────────────────────────────────────────
  function renderSettings(el) {
    const nw = state.config?.network || { mode: "direct", bypass: [], request_timeout_secs: 45 };
    const explicitProxy = nw.mode === "socks5" || nw.mode === "http-proxy";
    el.innerHTML = `
      <div class="page-head"><div><h1>${t("st.title")}</h1><div class="sub">${t("st.sub")}</div></div></div>
      <div class="card">
        <div class="setting-row">
          <div><div class="s-title">${t("st.lang")}</div><div class="s-desc">${t("st.lang.desc")}</div></div>
          <div class="seg" id="lang-seg">
            <button data-lang="zh" class="${state.lang === "zh" ? "active" : ""}">中文</button>
            <button data-lang="en" class="${state.lang === "en" ? "active" : ""}">English</button>
          </div>
        </div>
        <div class="setting-row">
          <div><div class="s-title">${t("st.theme")}</div><div class="s-desc">${t("st.theme.desc")}</div></div>
          <span class="chip" style="background:rgba(99,102,241,.12);color:var(--violet);border:1px solid rgba(99,102,241,.3)">${t("st.theme.dark")}</span>
        </div>
        <div class="setting-row">
          <div><div class="s-title">${t("st.update")} · v${esc(state.version)}</div><div class="s-desc">${t("st.update.desc")}</div></div>
          <button class="btn btn-ghost" id="check-update">${t("st.update")}</button>
        </div>
      </div>

      <div class="card">
        <h2 class="card-title">${t("st.network")}</h2>
        <p class="card-desc">${t("st.network.desc")}</p>
        <div class="grid-2">
          <div class="field">
            <label class="field-label">${t("st.network.mode")}</label>
            <select id="nw-mode">
              <option value="direct" ${nw.mode === "direct" ? "selected" : ""}>${t("st.network.direct")}</option>
              <option value="system" ${nw.mode === "system" ? "selected" : ""}>${t("st.network.system")}</option>
              <option value="socks5" ${nw.mode === "socks5" ? "selected" : ""}>SOCKS5</option>
              <option value="http-proxy" ${nw.mode === "http-proxy" ? "selected" : ""}>HTTP / HTTPS Proxy</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">${t("st.network.state")}</label>
            <div class="chip ${explicitProxy ? "" : "chip-exp"}">${esc(nw.proxy_endpoint || t("st.network.noProxy"))}</div>
          </div>
        </div>
        <div id="nw-explicit" style="${explicitProxy ? "" : "display:none"}">
          <div class="grid-2">
            <div class="field"><label class="field-label">${t("st.network.host")}</label>
              <input id="nw-host" value="${esc(nw.host || "127.0.0.1")}" autocomplete="off" /></div>
            <div class="field"><label class="field-label">${t("st.network.port")}</label>
              <input id="nw-port" type="number" min="1" max="65535" value="${esc(nw.port || 10808)}" /></div>
            <div class="field"><label class="field-label">${t("st.network.username")}</label>
              <input id="nw-user" value="${esc(nw.username || "")}" autocomplete="off" /></div>
            <div class="field"><label class="field-label">${t("st.network.password")}</label>
              <input id="nw-password" type="password" value="" placeholder="${t("st.network.password.ph")}" autocomplete="new-password" /></div>
          </div>
          <label class="check-row"><input id="nw-remote-dns" type="checkbox" ${nw.remote_dns !== false ? "checked" : ""} />
            <span>${t("st.network.remoteDns")}</span></label>
          <label class="check-row"><input id="nw-fallback" type="checkbox" disabled />
            <span>${t("st.network.fallback")}</span></label>
          <div class="field mt12"><label class="field-label">${t("st.network.bypass")}</label>
            <input id="nw-bypass" value="${esc((nw.bypass || []).join(","))}" placeholder="localhost,127.0.0.0/8,::1" /></div>
        </div>
        <div style="display:flex;gap:10px;margin-top:14px">
          <button class="btn btn-primary" id="save-network">${t("common.save")}</button>
          <button class="btn btn-ghost" id="test-network">${t("st.network.test")}</button>
        </div>
        <div id="network-results" class="mono mt12" style="font-size:12px;color:var(--text-2)"></div>
      </div>

      <div class="card about-block">
        <svg class="brand-mark" viewBox="0 0 48 48">
          <path d="M5 24 Q24 8 43 24" fill="none" stroke="#6366f1" stroke-width="2.6" stroke-linecap="round"/>
          <path d="M5 24 Q24 40 43 24" fill="none" stroke="#22d3ee" stroke-width="2.6" stroke-linecap="round" opacity=".85"/>
          <circle cx="24" cy="24" r="3.4" fill="#e0f2fe"/>
        </svg>
        <div style="font-weight:650;font-size:14.5px;margin-top:8px;color:var(--text)">veilweave <span class="mono" style="color:var(--muted);font-size:12px">v${esc(state.version)}</span></div>
        <div class="mt8">${t("st.about.desc")}</div>
        <div class="mt8"><a id="repo-link">${REPO_URL.replace("https://", "")}</a></div>
      </div>`;

    el.querySelectorAll("#lang-seg button").forEach((b) => (b.onclick = () => setLang(b.dataset.lang)));
    el.querySelector("#nw-mode").onchange = (event) => {
      const explicit = event.target.value === "socks5" || event.target.value === "http-proxy";
      el.querySelector("#nw-explicit").style.display = explicit ? "" : "none";
    };
    el.querySelector("#save-network").onclick = async (event) => {
      const btn = event.currentTarget;
      const mode = el.querySelector("#nw-mode").value;
      const explicit = mode === "socks5" || mode === "http-proxy";
      const settings = {
        mode,
        host: explicit ? el.querySelector("#nw-host").value.trim() : null,
        port: explicit ? Number(el.querySelector("#nw-port").value) : null,
        username: explicit ? (el.querySelector("#nw-user").value.trim() || null) : null,
        password: explicit ? (el.querySelector("#nw-password").value || null) : null,
        remote_dns: explicit ? el.querySelector("#nw-remote-dns").checked : true,
        allow_direct_fallback: false,
        bypass: explicit ? el.querySelector("#nw-bypass").value.split(",").map((value) => value.trim()).filter(Boolean) : [],
        connect_timeout_secs: 10,
        request_timeout_secs: nw.request_timeout_secs || 45,
        http_scheme: "http",
      };
      btn.disabled = true;
      try {
        await invoke("save_network", { settings });
        el.querySelector("#nw-password").value = "";
        toast(t("st.network.saved"), "success");
        await loadConfig();
        renderSettings(el);
      } catch (err) {
        toast(String(err), "error", 7000);
        btn.disabled = false;
      }
    };
    el.querySelector("#test-network").onclick = async (event) => {
      const btn = event.currentTarget;
      btn.disabled = true;
      try {
        const report = await invoke("test_network");
        el.querySelector("#network-results").innerHTML = report.checks.map((check) =>
          `<div style="display:flex;gap:12px"><span style="width:150px">${esc(check.name)}</span><b style="color:${check.ok ? "var(--green)" : "var(--red)"}">${check.ok ? "OK" : "FAIL"}</b><span>${esc(check.latency_ms)} ms · ${esc(check.detail)}</span></div>`
        ).join("");
      } catch (err) {
        toast(String(err), "error", 7000);
      }
      btn.disabled = false;
    };
    el.querySelector("#check-update").onclick = async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      btn.innerHTML = `<span class="spinner dark"></span> ${t("st.update.checking")}`;
      try {
        const r = await invoke("check_update");
        toast(String(r), "success", 6000);
      } catch (err) {
        toast(String(err), "info", 6000); // updater 404s until the pubkey is injected — not an app error
      }
      btn.disabled = false;
      btn.textContent = t("st.update");
    };
    el.querySelector("#repo-link").onclick = () => invoke("open_url", { url: REPO_URL });
  }

  function setLang(lang) {
    state.lang = lang;
    localStorage.setItem("vw-lang", lang);
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    invoke("set_ui_language", { language: lang }).catch(() => {});
    renderNavText();
    renderPage();
  }

  // ── deploy events ─────────────────────────────────────────────────────
  listen("deploy-log", (ev) => {
    state.deploy.logs.push(ev.payload);
    if (state.page === "deploy" && state.deploy.started) {
      const el = document.querySelector('.page[data-page="deploy"]');
      const box = el && el.querySelector("#deploy-log");
      if (box) {
        const l = ev.payload;
        box.insertAdjacentHTML("beforeend",
          `<div class="log-line log-${l.kind}"><span class="tag">${l.kind}</span><span class="msg">${esc(l.message)}</span></div>`);
        box.scrollTop = box.scrollHeight;
      }
    }
  });

  listen("deploy-done", async (ev) => {
    state.deploy.running = false;
    state.deploy.done = ev.payload;
    await loadConfig().catch(() => {});
    if (state.page === "deploy" && state.deploy.started) {
      renderDeployRun(document.querySelector('.page[data-page="deploy"]'));
    }
    if (ev.payload.ok) toast(t("dp.success"), "success");
    else toast(t("dp.failed"), "error", 6000);
  });

  // ── init ──────────────────────────────────────────────────────────────
  async function init() {
    document.querySelectorAll(".nav-item").forEach((n) => (n.onclick = () => setPage(n.dataset.nav)));
    document.getElementById("lang-toggle").onclick = () => setLang(state.lang === "zh" ? "en" : "zh");
    try { state.version = await invoke("app_version"); } catch { state.version = "2.0.0"; }
    document.getElementById("sidebar-version").textContent = "v" + state.version;
    renderNavText();
    await loadConfig().catch((e) => toast(String(e), "error"));
    // honor the language stored in the config file on first run
    if (!localStorage.getItem("vw-lang") && state.config && state.config.ui_language) {
      state.lang = state.config.ui_language;
      renderNavText();
    }
    setPage("overview");
  }

  init();
})();
