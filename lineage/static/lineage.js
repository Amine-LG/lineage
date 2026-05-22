/* Lineage v1.0 — sortable + filterable tables, tabs. No framework. */

(function () {
  "use strict";

  var THEME_KEY = "lineage-theme";

  function storedTheme() {
    try {
      return localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark";
    } catch (e) {
      return "dark";
    }
  }

  function applyTheme(theme, persist) {
    document.documentElement.dataset.theme = theme;
    if (persist) {
      try { localStorage.setItem(THEME_KEY, theme); } catch (e) {}
    }
    var toggle = document.getElementById("theme-toggle");
    if (!toggle) return;
    var isDark = theme === "dark";
    toggle.setAttribute("aria-pressed", isDark ? "true" : "false");
    toggle.setAttribute("aria-label", isDark ? "Switch to light mode" : "Switch to dark mode");
    toggle.title = isDark ? "Switch to light mode" : "Switch to dark mode";
    var label = toggle.querySelector(".theme-label");
    if (label) label.textContent = isDark ? "Dark" : "Light";
  }

  function attachThemeToggle() {
    applyTheme(storedTheme(), false);
    var toggle = document.getElementById("theme-toggle");
    if (!toggle) return;
    toggle.addEventListener("click", function () {
      var current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
      applyTheme(current === "dark" ? "light" : "dark", true);
    });
  }

  // -------- Sortable tables --------
  function parseValue(td) {
    var raw = td.dataset.sort;
    if (raw === undefined) raw = td.textContent.trim();
    // ISO timestamp? Compare as a string so chronological order is
    // preserved. parseFloat would otherwise truncate "2025-06-01..."
    // to 2025, tying every row in the same year.
    if (/^\d{4}-\d{2}-\d{2}/.test(raw)) return raw;
    var n = parseFloat(raw);
    return isNaN(n) ? raw.toLowerCase() : n;
  }

  function sortTable(table, colIndex, asc) {
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var rows = Array.prototype.slice.call(tbody.rows);
    rows.sort(function (a, b) {
      var av = parseValue(a.cells[colIndex]);
      var bv = parseValue(b.cells[colIndex]);
      if (av < bv) return asc ? -1 : 1;
      if (av > bv) return asc ? 1 : -1;
      return 0;
    });
    rows.forEach(function (r) { tbody.appendChild(r); });
  }

  function attachSort(table) {
    if (table.dataset.sortAttached === "1") return;
    table.dataset.sortAttached = "1";
    table.classList.add("sortable");
    var ths = table.tHead && table.tHead.rows[0]
      ? table.tHead.rows[0].cells : [];
    Array.prototype.forEach.call(ths, function (th, i) {
      if (th.dataset.nosort === "1") return;
      th.classList.add("sortable-th");
      th.addEventListener("click", function () {
        var current = th.dataset.sortDir || "";
        var asc = current !== "asc";
        Array.prototype.forEach.call(ths, function (other) {
          delete other.dataset.sortDir;
          other.classList.remove("sort-asc", "sort-desc");
        });
        th.dataset.sortDir = asc ? "asc" : "desc";
        th.classList.add(asc ? "sort-asc" : "sort-desc");
        sortTable(table, i, asc);
      });
    });
  }

  // -------- Filterable tables --------
  function attachFilter(input) {
    if (input.dataset.filterAttached === "1") return;
    input.dataset.filterAttached = "1";
    var sel = input.dataset.filterTarget;
    if (!sel) return;
    var table = document.querySelector(sel);
    if (!table) return;
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      var rows = table.tBodies[0] ? table.tBodies[0].rows : [];
      var visible = 0;
      Array.prototype.forEach.call(rows, function (r) {
        var match = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
        r.style.display = match ? "" : "none";
        if (match) visible++;
      });
      var counter = document.querySelector(input.dataset.filterCounter || "");
      if (counter) counter.textContent = visible;
    });
  }

  function cssEscape(value) {
    if (window.CSS && window.CSS.escape) return window.CSS.escape(value);
    return value.replace(/[^a-zA-Z0-9_-]/g, "\\$&");
  }

  function ensureTableEnhancements(table, index) {
    if (!table.tBodies[0]) return;
    attachSort(table);
    if (table.classList.contains("no-filter") || table.dataset.noFilter === "1") return;

    if (!table.id) table.id = "lineage-table-" + index;
    var selector = "#" + cssEscape(table.id);
    if (document.querySelector('input[data-filter-target="' + selector + '"]')) return;

    var shell = table.closest(".table-shell");
    if (!shell) {
      shell = document.createElement("div");
      shell.className = "table-shell";
      table.parentNode.insertBefore(shell, table);
      shell.appendChild(table);
    }

    var controls = shell.querySelector(":scope > .table-controls");
    if (!controls) {
      controls = document.createElement("div");
      controls.className = "table-controls";
      shell.insertBefore(controls, table);
    }

    var input = document.createElement("input");
    input.type = "search";
    input.className = "table-filter";
    input.placeholder = "Filter table...";
    input.setAttribute("aria-label", "Filter table");
    input.dataset.filterTarget = selector;
    controls.appendChild(input);
    attachFilter(input);
  }

  // -------- Tabs --------
  function attachTabs(group) {
    var buttons = group.querySelectorAll("[data-tab]");
    var panels = document.querySelectorAll("[data-tab-panel]");
    function show(name) {
      buttons.forEach(function (b) {
        b.classList.toggle("active", b.dataset.tab === name);
      });
      panels.forEach(function (p) {
        p.style.display = p.dataset.tabPanel === name ? "" : "none";
      });
    }
    buttons.forEach(function (b) {
      b.addEventListener("click", function () { show(b.dataset.tab); });
    });
    var initial = group.dataset.tabInitial || (buttons[0] && buttons[0].dataset.tab);
    if (initial) show(initial);
  }

  document.addEventListener("DOMContentLoaded", function () {
    attachThemeToggle();
    document.querySelectorAll("table.dense").forEach(ensureTableEnhancements);
    document.querySelectorAll("input[data-filter-target]").forEach(attachFilter);
    document.querySelectorAll(".tabs").forEach(attachTabs);
  });
})();
