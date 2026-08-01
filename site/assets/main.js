(() => {
  const BASE = (() => {
    const parts = location.pathname.split("/").filter(Boolean);
    // Project Pages: /go-jenkins-mcp/...  Local preview: /
    if (parts[0] === "go-jenkins-mcp") return "/go-jenkins-mcp";
    return "";
  })();

  // Rewrite data-href and data-base links once DOM is ready
  function withBase(path) {
    if (!path || path.startsWith("http") || path.startsWith("#")) return path;
    if (path.startsWith("/")) return `${BASE}${path}`;
    return path;
  }

  document.querySelectorAll("[data-base]").forEach((el) => {
    const href = el.getAttribute("href");
    if (href) el.setAttribute("href", withBase(href));
    const src = el.getAttribute("src");
    if (src && src.startsWith("/")) el.setAttribute("src", withBase(src));
  });

  // Mark active nav
  const path = location.pathname.replace(/\/$/, "") || "/";
  const leaf = path.endsWith(".html")
    ? path.split("/").pop()
    : path.endsWith("go-jenkins-mcp") || path === "" || path === "/"
      ? "index.html"
      : path.split("/").pop() || "index.html";

  document.querySelectorAll("[data-nav]").forEach((a) => {
    const target = a.getAttribute("data-nav");
    if (target === leaf || (leaf === "" && target === "index.html")) {
      a.setAttribute("aria-current", "page");
    }
  });

  // Mobile nav
  const toggle = document.querySelector("[data-nav-toggle]");
  const mobile = document.querySelector("[data-mobile-nav]");
  if (toggle && mobile) {
    toggle.addEventListener("click", () => {
      const open = mobile.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  // Reveal on scroll
  const reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && reveals.length) {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
    );
    reveals.forEach((el) => io.observe(el));
  } else {
    reveals.forEach((el) => el.classList.add("visible"));
  }

  // Copy buttons
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const sel = btn.getAttribute("data-copy");
      const node = sel ? document.querySelector(sel) : null;
      const text = node ? node.textContent : "";
      try {
        await navigator.clipboard.writeText(text.trim());
        const prev = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.textContent = prev;
        }, 1400);
      } catch {
        btn.textContent = "Copy failed";
      }
    });
  });
})();
