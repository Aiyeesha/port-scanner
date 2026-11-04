// ─────────────────────────────────────────────────────────────
// Interface web locale de port-scanner — logique de la page.
//
// Règles de sécurité appliquées ici :
//  - le jeton est lu dans le FRAGMENT de l'URL (#token=…), jamais envoyé au serveur
//    autrement que dans l'en-tête X-Scan-Token ; il est ensuite retiré de la barre
//    d'adresse pour ne pas rester visible ni partir dans l'historique partagé ;
//  - toute donnée issue d'un scan est insérée avec textContent (jamais innerHTML) :
//    une bannière piégée ne peut pas injecter de HTML ni de script.
// ─────────────────────────────────────────────────────────────
"use strict";

// ── 1. Textes bilingues ─────────────────────────────────────
const I18N = {
  fr: {
    legal: "À n'utiliser que sur vos propres systèmes ou avec une autorisation écrite. L'interface web n'accepte que les réseaux privés et la boucle locale.",
    noToken: "Jeton absent : ouvrez le lien complet affiché par la commande « port-scanner-web ».",
    targets: "Cibles",
    targetsHelp: "IP, réseau CIDR ou nom d'hôte, séparés par des espaces ou des virgules.",
    ports: "Ports",
    portsHelp: "22 · 20-25 · 22,80,443 · top100 · well-known · all",
    timeout: "Délai (s)",
    concurrency: "Concurrence",
    banners: "Lire les bannières (plus lent, plus visible)",
    all: "Afficher aussi les ports fermés et filtrés",
    run: "Lancer le scan",
    running: "Scan en cours…",
    results: "Résultats",
    export: "Exporter en JSON",
    colAddress: "Adresse", colPort: "Port", colState: "État", colService: "Service",
    colRisk: "Risque", colLatency: "Latence", colBanner: "Bannière",
    empty: "Aucun port ouvert trouvé.",
    summary: (d) => `${d.targets} adresse(s) × ${d.ports_per_target} port(s) en ${d.duration_s.toFixed(2)} s — ${d.summary.open} ouvert(s), ${d.summary.closed} fermé(s), ${d.summary.filtered} filtré(s).`,
    states: { open: "ouvert", closed: "fermé", filtered: "filtré" },
    risks: { info: "info", low: "faible", medium: "moyen", high: "élevé", critical: "critique" },
    network: "Serveur injoignable : la commande port-scanner-web est-elle toujours lancée ?",
    footer: "Serveur local uniquement · aucune donnée ne quitte votre machine en dehors des connexions de scan.",
  },
  en: {
    legal: "Only use on systems you own or with written authorisation. The web interface only accepts private networks and loopback.",
    noToken: "Missing token: open the full link printed by the “port-scanner-web” command.",
    targets: "Targets",
    targetsHelp: "IP, CIDR network or hostname, separated by spaces or commas.",
    ports: "Ports",
    portsHelp: "22 · 20-25 · 22,80,443 · top100 · well-known · all",
    timeout: "Timeout (s)",
    concurrency: "Concurrency",
    banners: "Grab banners (slower, more visible)",
    all: "Also show closed and filtered ports",
    run: "Start scan",
    running: "Scanning…",
    results: "Results",
    export: "Export JSON",
    colAddress: "Address", colPort: "Port", colState: "State", colService: "Service",
    colRisk: "Risk", colLatency: "Latency", colBanner: "Banner",
    empty: "No open port found.",
    summary: (d) => `${d.targets} address(es) × ${d.ports_per_target} port(s) in ${d.duration_s.toFixed(2)} s — ${d.summary.open} open, ${d.summary.closed} closed, ${d.summary.filtered} filtered.`,
    states: { open: "open", closed: "closed", filtered: "filtered" },
    risks: { info: "info", low: "low", medium: "medium", high: "high", critical: "critical" },
    network: "Server unreachable: is the port-scanner-web command still running?",
    footer: "Local server only · no data leaves your machine apart from the scan connections.",
  },
};

// ── 2. État de la page ──────────────────────────────────────
const $ = (id) => document.getElementById(id);
let lang = "fr";
let lastDocument = null; // dernier résultat, pour l'export et le changement de langue

// Préférence de langue : simple confort, l'accès au stockage peut échouer (navigation privée)
try { lang = localStorage.getItem("ps-lang") === "en" ? "en" : "fr"; } catch { /* sans effet */ }

// Lecture du jeton dans le fragment, puis nettoyage de la barre d'adresse
const token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
if (token) history.replaceState(null, "", location.pathname);

// ── 3. Traduction de la page ────────────────────────────────
function t(key) { return I18N[lang][key]; }

function applyLanguage() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $("lang").textContent = lang === "fr" ? "EN" : "FR";
  if (lastDocument) render(lastDocument);
}

// ── 4. Appels à l'API ───────────────────────────────────────
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "X-Scan-Token": token, ...(options.body ? { "Content-Type": "application/json" } : {}) },
    cache: "no-store",
    credentials: "omit",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

// ── 5. Affichage des résultats (textContent uniquement) ─────
function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function render(doc) {
  const rows = $("rows");
  rows.replaceChildren(); // vide le tableau sans manipuler de HTML
  for (const r of doc.results) {
    const tr = document.createElement("tr");
    const isOpen = r.state === "open";
    tr.append(
      cell(r.source === r.address ? r.address : `${r.address} (${r.source})`),
      cell(`${r.port}/tcp`, "num"),
      cell(t("states")[r.state] ?? r.state, `state state-${r.state}`),
      cell(r.service),
      cell(isOpen ? (t("risks")[r.risk] ?? r.risk) : "–", isOpen ? `risk risk-${r.risk}` : "muted"),
      cell(r.latency_ms == null ? "–" : `${r.latency_ms} ms`, "num"),
      cell(r.banner ?? "", "banner"),
    );
    rows.append(tr);
  }
  $("summary").textContent = t("summary")(doc);
  $("empty").hidden = doc.results.length > 0;
  $("results").hidden = false;
}

// ── 6. Lancement d'un scan ──────────────────────────────────
async function onSubmit(event) {
  event.preventDefault();
  const button = $("run");
  button.disabled = true;
  $("status").textContent = t("running");
  try {
    const doc = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify({
        targets: $("targets").value,
        ports: $("ports").value,
        timeout: Number($("timeout").value),
        concurrency: Number($("concurrency").value),
        banners: $("banners").checked,
        all: $("all").checked,
      }),
    });
    lastDocument = doc;
    render(doc);
    $("status").textContent = "";
  } catch (error) {
    $("status").textContent = error instanceof TypeError ? t("network") : error.message;
  } finally {
    button.disabled = false;
  }
}

// ── 7. Export JSON (fichier généré localement par le navigateur) ──
function onExport() {
  if (!lastDocument) return;
  const blob = new Blob([JSON.stringify(lastDocument, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `scan-${lastDocument.started_at.replaceAll(":", "-")}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

// ── 8. Démarrage ────────────────────────────────────────────
async function init() {
  applyLanguage();
  $("lang").addEventListener("click", () => {
    lang = lang === "fr" ? "en" : "fr";
    try { localStorage.setItem("ps-lang", lang); } catch { /* sans effet */ }
    applyLanguage();
  });
  $("scan-form").addEventListener("submit", onSubmit);
  $("export").addEventListener("click", onExport);

  if (!token) {
    $("no-token").hidden = false;
    $("run").disabled = true;
    return;
  }
  try {
    const meta = await api("/api/meta");
    $("version").textContent = `v${meta.version}`;
    for (const name of meta.presets) {
      const option = document.createElement("option");
      option.value = name;
      $("presets").append(option);
    }
  } catch (error) {
    $("status").textContent = error.message;
    $("run").disabled = true;
  }
}

document.addEventListener("DOMContentLoaded", init);
