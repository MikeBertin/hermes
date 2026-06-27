// Hermes — shared hover-to-explain popover. Each demo defines a global POPS map
// { key: "<h4>Title</h4><p>body</p>" } and marks terms with
// <span class="x" data-pop="key">…</span>.
(function () {
  "use strict";
  const pop = document.createElement("div");
  pop.id = "pop";
  document.addEventListener("DOMContentLoaded", () => document.body.appendChild(pop));

  function show(el) {
    const key = el.getAttribute("data-pop");
    const html = (window.POPS || {})[key];
    if (!html) return;
    pop.innerHTML = html;
    pop.classList.add("show");
    const r = el.getBoundingClientRect();
    const pr = pop.getBoundingClientRect();
    let left = r.left + r.width / 2 - pr.width / 2;
    left = Math.max(10, Math.min(left, window.innerWidth - pr.width - 10));
    let top = r.bottom + 8;
    if (top + pr.height > window.innerHeight - 10) top = r.top - pr.height - 8;
    pop.style.left = left + "px";
    pop.style.top = top + "px";
  }
  const hide = () => pop.classList.remove("show");

  document.addEventListener("mouseover", (e) => {
    const el = e.target.closest(".x");
    if (el) show(el);
  });
  document.addEventListener("mouseout", (e) => {
    if (e.target.closest(".x")) hide();
  });
})();
