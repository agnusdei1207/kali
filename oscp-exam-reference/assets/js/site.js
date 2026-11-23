(function () {
  "use strict";

  var root = document.documentElement;
  var body = document.body;

  function storedTheme() {
    try {
      return localStorage.getItem("theme");
    } catch (e) {
      return null;
    }
  }

  function applyTheme(theme, persist) {
    root.dataset.theme = theme;
    if (persist) {
      try {
        localStorage.setItem("theme", theme);
      } catch (e) {
        /* ignore */
      }
    }
    document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
      var next = theme === "dark" ? "Light" : "Dark";
      button.setAttribute("aria-label", "Switch to " + next + " mode");
      button.setAttribute("title", "Switch to " + next + " mode");
    });
  }

  applyTheme(root.dataset.theme || "dark", false);

  document.querySelectorAll("[data-theme-toggle]").forEach(function (button) {
    button.addEventListener("click", function () {
      applyTheme(root.dataset.theme === "dark" ? "light" : "dark", true);
    });
  });

  var colorScheme = window.matchMedia("(prefers-color-scheme: dark)");
  if (colorScheme.addEventListener) {
    colorScheme.addEventListener("change", function (event) {
      if (!storedTheme()) {
        applyTheme(event.matches ? "dark" : "light", false);
      }
    });
  }

  /* Mobile navigation */

  var navToggle = document.querySelector("[data-nav-toggle]");
  var navClosers = document.querySelectorAll("[data-nav-close]");

  function setNav(open) {
    body.classList.toggle("nav-open", open);
    if (navToggle) {
      navToggle.setAttribute("aria-expanded", String(open));
      navToggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    }
  }

  if (navToggle) {
    navToggle.addEventListener("click", function () {
      setNav(!body.classList.contains("nav-open"));
    });
  }

  navClosers.forEach(function (el) {
    el.addEventListener("click", function () {
      setNav(false);
    });
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      setNav(false);
    }

    var typing =
      event.target &&
      (event.target.tagName === "INPUT" ||
        event.target.tagName === "TEXTAREA" ||
        event.target.tagName === "SELECT" ||
        event.target.isContentEditable);

    if (event.key === "/" && !typing) {
      var searchInput = document.getElementById("search-input");
      if (searchInput) {
        event.preventDefault();
        searchInput.focus();
      } else {
        var searchLink = document.querySelector("[data-search-link]");
        if (searchLink) {
          event.preventDefault();
          window.location.href = searchLink.href;
        }
      }
    }
  });

  /* Copy buttons for code blocks */

  function legacyCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.top = "-9999px";
    document.body.appendChild(area);
    area.select();
    try {
      document.execCommand("copy");
    } catch (e) {
      /* ignore */
    }
    document.body.removeChild(area);
  }

  document.querySelectorAll(".prose pre").forEach(function (pre) {
    if (pre.parentElement && pre.parentElement.classList.contains("code-frame")) {
      return;
    }

    var frame = document.createElement("div");
    frame.className = "code-frame";
    pre.parentNode.insertBefore(frame, pre);
    frame.appendChild(pre);

    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy-code";
    button.textContent = "Copy";
    button.setAttribute("aria-label", "Copy code");
    frame.appendChild(button);

    button.addEventListener("click", function () {
      var text = pre.innerText;
      function done() {
        button.textContent = "Copied";
        window.setTimeout(function () {
          button.textContent = "Copy";
        }, 1600);
      }

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () {
          legacyCopy(text);
          done();
        });
      } else {
        legacyCopy(text);
        done();
      }
    });
  });

  /* Highlight the current heading in the table of contents */

  var tocLinks = Array.prototype.slice.call(
    document.querySelectorAll('.toc a[href^="#"]')
  );

  if (tocLinks.length && "IntersectionObserver" in window) {
    var linkById = new Map();

    tocLinks.forEach(function (link) {
      var id = decodeURIComponent(link.getAttribute("href").slice(1));
      var heading = document.getElementById(id);
      if (heading) {
        linkById.set(heading, link);
      }
    });

    var setActive = function (heading) {
      tocLinks.forEach(function (link) {
        link.classList.remove("active");
      });
      var link = linkById.get(heading);
      if (link) {
        link.classList.add("active");
      }
    };

    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            setActive(entry.target);
          }
        });
      },
      { rootMargin: "-80px 0px -72% 0px", threshold: 0 }
    );

    linkById.forEach(function (_, heading) {
      observer.observe(heading);
    });
  }
})();
