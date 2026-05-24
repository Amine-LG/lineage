/* Lineage top-nav jump-to search.
 *
 * Vanilla, no dependencies, no build step. The search index is fetched
 * lazily on first focus (or '/' shortcut), then all matching happens
 * client-side. All rendering uses textContent / element creation so
 * untrusted object names cannot inject markup.
 */
(function () {
  "use strict";

  var input = document.getElementById("nav-search-input");
  var box   = document.getElementById("nav-search-results");
  if (!input || !box) return;

  var INDEX = null;          // populated on first focus
  var LOADING = false;
  var SELECTED = -1;
  var CURRENT_RESULTS = [];
  var MIN_QUERY_LEN = 2;     // 1-char queries are too noisy to be useful

  // Primary kinds first, then noisier "secondary" ones. Within a tie on
  // match score, this order determines what shows up nearer the top of
  // the dropdown. Score still wins overall (an exact match on an image
  // outranks a substring match on a User).
  var KIND_ORDER = [
    "User", "Group", "ServiceAccount", "Identity",
    "Namespace", "SCC",
    "ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding",
    "Workload", "Image", "ImageStream"
  ];

  /* ───────────────────────── helpers ───────────────────────── */

  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function ensureIndexLoaded() {
    if (INDEX || LOADING) return;
    LOADING = true;
    fetch("/search-index.json", { credentials: "same-origin" })
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (items) {
        // Normalize tokens to lowercase once. Original `display` and
        // `kind` stay untouched for rendering.
        INDEX = items.map(function (it) {
          var tokens = (it.tokens || []).map(function (t) {
            return String(t || "").toLowerCase();
          });
          return {
            id: it.id,
            kind: it.kind,
            display: it.display,
            namespace: it.namespace,
            description: it.description,
            url: it.url,
            tokens: tokens,
            display_lc: String(it.display || "").toLowerCase()
          };
        });
        LOADING = false;
        if (input === document.activeElement) doSearch(input.value);
      })
      .catch(function () {
        LOADING = false;
        renderError();
      });
  }

  /* ───────────────────────── matching ──────────────────────── */

  function score(item, q) {
    if (item.display_lc === q) return 0;
    for (var i = 0; i < item.tokens.length; i++) {
      if (item.tokens[i] === q) return 1;
    }
    if (item.display_lc.indexOf(q) === 0) return 2;
    for (var j = 0; j < item.tokens.length; j++) {
      if (item.tokens[j].indexOf(q) === 0) return 3;
    }
    if (item.display_lc.indexOf(q) !== -1) return 4;
    for (var k = 0; k < item.tokens.length; k++) {
      if (item.tokens[k].indexOf(q) !== -1) return 5;
    }
    return -1;
  }

  function filter(q) {
    var hits = [];
    for (var i = 0; i < INDEX.length; i++) {
      var s = score(INDEX[i], q);
      if (s >= 0) hits.push({ s: s, item: INDEX[i] });
    }
    hits.sort(function (a, b) {
      if (a.s !== b.s) return a.s - b.s;
      var ka = KIND_ORDER.indexOf(a.item.kind);
      var kb = KIND_ORDER.indexOf(b.item.kind);
      if (ka !== kb) return ka - kb;
      return a.item.display_lc.localeCompare(b.item.display_lc);
    });
    // Cap to avoid huge dropdowns
    return hits.slice(0, 30).map(function (h) { return h.item; });
  }

  /* ───────────────────────── rendering ─────────────────────── */

  function clearBox() {
    while (box.firstChild) box.removeChild(box.firstChild);
  }

  function renderEmpty() {
    clearBox();
    // Clear any leftover selection from a prior query — otherwise
    // pressing Enter from the hint state would navigate to a stale row.
    CURRENT_RESULTS = [];
    SELECTED = -1;
    var hint = el("div", "nav-search-hint");
    hint.appendChild(document.createTextNode(
      "Type 2+ characters. Try "));
    ["alice", "builder", "payments-prod", "cluster-admin"]
      .forEach(function (s) { hint.appendChild(el("code", null, s)); });
    box.appendChild(hint);
    open();
  }

  function renderError() {
    clearBox();
    CURRENT_RESULTS = [];
    SELECTED = -1;
    box.appendChild(el("div", "nav-search-empty",
      "Search unavailable — could not load index."));
    open();
  }

  function renderResults(results) {
    clearBox();
    CURRENT_RESULTS = results;
    if (results.length === 0) {
      box.appendChild(el("div", "nav-search-empty", "No matches."));
      SELECTED = -1;
      open();
      return;
    }
    var lastKind = null;
    results.forEach(function (it, i) {
      if (it.kind !== lastKind) {
        box.appendChild(el("div", "nav-search-group", it.kind));
        lastKind = it.kind;
      }
      var row = el("a", "nav-search-result");
      row.href = it.url;
      row.setAttribute("role", "option");
      row.dataset.index = String(i);
      // Long refs (image digests, etc.) truncate via CSS but the full
      // value is recoverable on hover. setAttribute is safe — the
      // string is not interpolated into HTML.
      row.setAttribute("title", it.display);
      row.appendChild(el("div", "nav-search-result-display", it.display));
      var metaParts = [];
      if (it.namespace && it.description &&
          it.description.indexOf(it.namespace) === -1) {
        metaParts.push(it.namespace);
      }
      if (it.description) metaParts.push(it.description);
      row.appendChild(el("div", "nav-search-result-meta", metaParts.join(" · ")));
      row.addEventListener("mouseenter", function () { setSelected(i); });
      box.appendChild(row);
    });
    SELECTED = 0;
    updateSelection();
    open();
  }

  function updateSelection() {
    var rows = box.querySelectorAll(".nav-search-result");
    for (var i = 0; i < rows.length; i++) {
      if (i === SELECTED) {
        rows[i].classList.add("selected");
        rows[i].scrollIntoView({ block: "nearest" });
      } else {
        rows[i].classList.remove("selected");
      }
    }
  }

  function setSelected(i) {
    SELECTED = i;
    updateSelection();
  }

  function open() {
    box.hidden = false;
    input.setAttribute("aria-expanded", "true");
  }

  function close() {
    box.hidden = true;
    input.setAttribute("aria-expanded", "false");
    SELECTED = -1;
  }

  function navigateSelected() {
    if (SELECTED < 0 || SELECTED >= CURRENT_RESULTS.length) return false;
    var url = CURRENT_RESULTS[SELECTED].url;
    if (!url) return false;
    window.location.href = url;
    return true;
  }

  /* ───────────────────────── search flow ───────────────────── */

  function doSearch(raw) {
    var q = (raw || "").trim().toLowerCase();
    if (!INDEX) {
      ensureIndexLoaded();
      renderEmpty();
      return;
    }
    // 1-character queries match too broadly to be useful (e.g. '/' hits
    // every image ref, 'a' hits hundreds of things). Show the hint
    // until the user has typed enough to navigate by.
    if (q.length < MIN_QUERY_LEN) { renderEmpty(); return; }
    renderResults(filter(q));
  }

  /* ───────────────────────── events ────────────────────────── */

  input.addEventListener("focus", function () {
    ensureIndexLoaded();
    doSearch(input.value);
  });

  input.addEventListener("input", function () {
    doSearch(input.value);
  });

  input.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      close();
      input.blur();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      if (CURRENT_RESULTS.length === 0) return;
      SELECTED = (SELECTED + 1) % CURRENT_RESULTS.length;
      updateSelection();
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (CURRENT_RESULTS.length === 0) return;
      SELECTED = (SELECTED - 1 + CURRENT_RESULTS.length) % CURRENT_RESULTS.length;
      updateSelection();
      return;
    }
    if (e.key === "Enter") {
      if (navigateSelected()) e.preventDefault();
    }
  });

  document.addEventListener("click", function (e) {
    if (!box.hidden && !box.contains(e.target) && e.target !== input) {
      close();
    }
  });

  // Global '/' shortcut to focus the search input. Skip when the user
  // is typing in another text field (so '/' is a literal char there),
  // BUT intercept when:
  //   - the search input itself has focus and is empty — without this,
  //     pressing '/' would type a literal '/' into search and trigger
  //     a flood of substring matches against image refs / imagestream
  //     displays (every one contains a '/'),
  //   - the search input has content (let '/' type, so e.g.
  //     'docker.io/library' still works).
  document.addEventListener("keydown", function (e) {
    if (e.key !== "/") return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target;
    var inOurInput = (t === input);
    var inOtherField = t && !inOurInput && (
      t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable);
    if (inOtherField) return;
    if (inOurInput && input.value !== "") return; // let '/' type mid-content
    e.preventDefault();
    input.focus();
    input.select();
  });
})();
