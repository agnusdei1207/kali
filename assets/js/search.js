(function () {
  "use strict";

  var input = document.getElementById("search-input");
  var statusEl = document.getElementById("search-status");
  var resultsEl = document.getElementById("search-results");

  if (!input || !statusEl || !resultsEl) {
    return;
  }

  var indexUrl = document.body.getAttribute("data-search-index");
  var docs = [];
  var ready = false;
  var timer = null;

  function normalize(value) {
    return (value || "").toLocaleLowerCase("en-US");
  }

  function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function appendHighlighted(parent, text, tokens) {
    if (!tokens.length) {
      parent.appendChild(document.createTextNode(text));
      return;
    }

    var pattern = new RegExp("(" + tokens.map(escapeRegExp).join("|") + ")", "gi");
    var parts = text.split(pattern);

    parts.forEach(function (part, index) {
      if (!part) {
        return;
      }
      if (index % 2 === 1) {
        var mark = document.createElement("mark");
        mark.textContent = part;
        parent.appendChild(mark);
      } else {
        parent.appendChild(document.createTextNode(part));
      }
    });
  }

  function makeSnippet(doc, tokens) {
    var summary = doc.summary || "";
    var content = doc.content || "";
    var source = summary;
    var lower = normalize(summary);
    var found = tokens.some(function (token) {
      return lower.indexOf(token) !== -1;
    });

    if (!found) {
      source = content;
      lower = normalize(content);
    }

    if (!source) {
      return "";
    }

    var index = -1;
    for (var i = 0; i < tokens.length; i += 1) {
      var at = lower.indexOf(tokens[i]);
      if (at !== -1 && (index === -1 || at < index)) {
        index = at;
      }
    }

    var start = Math.max(0, index === -1 ? 0 : index - 42);
    var end = Math.min(source.length, start + 180);
    var text = source.slice(start, end).replace(/\s+/g, " ").trim();

    return (start > 0 ? "… " : "") + text + (end < source.length ? " …" : "");
  }

  function render(results, tokens, query) {
    var fragment = document.createDocumentFragment();

    results.slice(0, 30).forEach(function (result) {
      var doc = result.doc;
      var link = document.createElement("a");
      link.className = "search-result";
      link.href = doc.url;

      var section = document.createElement("span");
      section.className = "search-result-section";
      section.textContent = doc.section || "Document";

      var title = document.createElement("span");
      title.className = "search-result-title";
      title.textContent = doc.title;

      link.appendChild(section);
      link.appendChild(title);

      var snippetText = makeSnippet(doc, tokens);
      if (snippetText) {
        var snippet = document.createElement("span");
        snippet.className = "search-result-snippet";
        appendHighlighted(snippet, snippetText, tokens);
        link.appendChild(snippet);
      }

      fragment.appendChild(link);
    });

    if (!results.length) {
      var empty = document.createElement("p");
      empty.className = "search-empty";
      empty.textContent = "No results for ‘" + query + "’. Try different keywords.";
      fragment.appendChild(empty);
    }

    resultsEl.replaceChildren(fragment);
    statusEl.textContent = results.length
      ? results.length + " results"
      : "No results";
  }

  function run() {
    var query = input.value.trim();

    if (!ready) {
      statusEl.textContent = "Loading search index…";
      return;
    }

    if (!query) {
      resultsEl.replaceChildren();
      statusEl.textContent = docs.length + " documents available to search.";
      return;
    }

    var tokens = normalize(query).split(/\s+/).filter(Boolean);
    var results = [];

    docs.forEach(function (doc) {
      var title = normalize(doc.title);
      var summary = normalize(doc.summary);
      var content = normalize(doc.content);
      var tags = normalize(doc.tags);
      var score = 0;
      var matchesAll = true;

      for (var i = 0; i < tokens.length; i += 1) {
        var token = tokens[i];
        var inTitle = title.indexOf(token) !== -1;
        var inTags = tags.indexOf(token) !== -1;
        var inSummary = summary.indexOf(token) !== -1;
        var inContent = content.indexOf(token) !== -1;

        if (!inTitle && !inTags && !inSummary && !inContent) {
          matchesAll = false;
          break;
        }

        score += inTitle ? 20 : 0;
        score += inTags ? 8 : 0;
        score += inSummary ? 5 : 0;
        score += inContent ? 1 : 0;
      }

      if (matchesAll) {
        results.push({ doc: doc, score: score });
      }
    });

    results.sort(function (a, b) {
      if (b.score !== a.score) {
        return b.score - a.score;
      }
      return a.doc.title.length - b.doc.title.length;
    });

    render(results, tokens, query);
  }

  input.addEventListener("input", function () {
    window.clearTimeout(timer);
    timer = window.setTimeout(run, 90);
  });

  var initial = new URLSearchParams(window.location.search).get("q");
  if (initial) {
    input.value = initial;
  }

  fetch(indexUrl, { credentials: "same-origin" })
    .then(function (response) {
      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }
      return response.json();
    })
    .then(function (data) {
      docs = Array.isArray(data) ? data : [];
      ready = true;
      input.focus();
      run();
    })
    .catch(function () {
      statusEl.textContent = "Failed to load the search index. Please refresh the page.";
    });
})();
