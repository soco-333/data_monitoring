/* BreachGuard dashboard — talks to the Flask routes in monitor.py:
 *   GET  /monitor/status
 *   POST /monitor/<type>/start          body: { value, interval_seconds, slot_index }
 *   POST /monitor/<type>/<index>/stop
 */

const POLL_MS = 1000;

function slotEl(type, index) {
  return document.querySelector(`.slot[data-slot-type="${type}"][data-slot-index="${index}"]`);
}

function maskIfPassword(type, value) {
  if (type !== "password" || !value) return value;
  if (value.length <= 2) return "*".repeat(value.length);
  return value.slice(0, 2) + "*".repeat(Math.max(3, value.length - 2));
}

function renderSlot(type, data) {
  const el = slotEl(type, data.slot_index);
  if (!el) return;

  const statusPill = el.querySelector('[data-role="status"]');
  const idleForm   = el.querySelector('[data-role="idle-form"]');
  const activeView = el.querySelector('[data-role="active-view"]');
  const ring       = el.querySelector('[data-role="ring"]');
  const ringText   = el.querySelector('[data-role="ring-text"]');
  const watchValue = el.querySelector('[data-role="watch-value"]');
  const lastCheck  = el.querySelector('[data-role="last-check"]');
  const findingsUl = el.querySelector('[data-role="findings"]');

  const hasFindings = data.findings && data.findings.length > 0;

  if (data.running) {
    idleForm.hidden = true;
    activeView.hidden = false;

    statusPill.textContent = hasFindings ? "BREACHED" : "MONITORING";
    statusPill.classList.toggle("is-breach", hasFindings);
    statusPill.classList.toggle("is-running", !hasFindings);

    const remaining = data.seconds_remaining ?? 0;
    const pct = data.interval_seconds
      ? Math.max(0, 100 - (remaining / data.interval_seconds) * 100)
      : 0;
    ring.style.setProperty("--pct", pct.toFixed(1));
    ringText.textContent = `${remaining}s`;

    watchValue.textContent = maskIfPassword(type, data.value);
    lastCheck.textContent = data.last_checked_at
      ? `last check: ${data.last_checked_at.replace("T", " ")}`
      : "last check: pending…";
  } else {
    idleForm.hidden = false;
    activeView.hidden = true;
    statusPill.textContent = "IDLE";
    statusPill.classList.remove("is-running", "is-breach");
  }

  findingsUl.innerHTML = "";
  if (hasFindings) {
    data.findings
      .slice()
      .reverse()
      .forEach((f) => {
        const li = document.createElement("li");
        li.className = "finding-item";
        li.innerHTML = `<span>match in ${f.source}</span><span class="ts">${f.timestamp}</span>`;
        findingsUl.appendChild(li);
      });
  }
}

async function pollStatus() {
  try {
    const res = await fetch("/monitor/status");
    if (!res.ok) throw new Error(`status ${res.status}`);
    const data = await res.json();

    data.emails.forEach((s) => renderSlot("email", s));
    data.passwords.forEach((s) => renderSlot("password", s));

    setConn(true);
  } catch (err) {
    setConn(false);
  }
}

function setConn(ok) {
  const dot = document.getElementById("conn-dot");
  const text = document.getElementById("conn-text");
  if (!dot || !text) return;
  dot.style.background = ok ? "var(--green)" : "var(--danger)";
  dot.style.boxShadow = ok ? "0 0 8px var(--green)" : "0 0 8px var(--danger)";
  text.textContent = ok ? "LIVE MONITOR" : "CONNECTION LOST";
}

async function startSlot(type, index, value) {
  const btn = slotEl(type, index).querySelector('[data-role="start-btn"]');
  btn.disabled = true;
  try {
    const res = await fetch(`/monitor/${type}/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ value, slot_index: index }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert(err.error || `Could not start monitoring (status ${res.status})`);
    }
    await pollStatus();
  } finally {
    btn.disabled = false;
  }
}

async function stopSlot(type, index) {
  await fetch(`/monitor/${type}/${index}/stop`, { method: "POST" });
  await pollStatus();
}

function wireControls() {
  document.querySelectorAll(".slot").forEach((el) => {
    const type = el.dataset.slotType;
    const index = parseInt(el.dataset.slotIndex, 10);

    const startBtn = el.querySelector('[data-role="start-btn"]');
    const stopBtn = el.querySelector('[data-role="stop-btn"]');
    const input = el.querySelector('[data-role="value-input"]');

    startBtn.addEventListener("click", () => {
      const value = input.value.trim();
      if (!value) {
        input.focus();
        return;
      }
      startSlot(type, index, value);
    });

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") startBtn.click();
    });

    stopBtn.addEventListener("click", () => stopSlot(type, index));
  });
}

wireControls();
pollStatus();
setInterval(pollStatus, POLL_MS);