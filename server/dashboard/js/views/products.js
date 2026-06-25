const ProductsView = {
  state: { offset: 0, limit: 50, filter: "" },

  async render(el) {
    const s = this.state;

    el.innerHTML = `
      <div class="page-header">
        <h2>Products</h2>
      </div>
      <div class="search-bar">
        <input type="search" id="product-filter" placeholder="Filter products..." value="${s.filter}">
        <span class="hint">Case-insensitive substring match</span>
      </div>
      <div class="card">
        <div class="table-wrap" id="products-table">${App.skeleton(8)}</div>
        <div class="pagination" id="products-pag"></div>
      </div>`;

    const input = document.getElementById("product-filter");
    let debounce;
    input.addEventListener("input", () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        s.filter = input.value;
        s.offset = 0;
        this.load();
      }, 300);
    });

    await this.load();
  },

  async load() {
    const s = this.state;
    const tableEl = document.getElementById("products-table");
    const pagEl = document.getElementById("products-pag");
    if (!tableEl) return;

    try {
      const params = { limit: s.limit, offset: s.offset };
      if (s.filter) params.name = `%${s.filter}%`;
      const data = await API.products(s.limit, s.offset);

      let products = data.products || data;
      if (s.filter) {
        const f = s.filter.toLowerCase();
        products = products.filter(p => p.name.toLowerCase().includes(f) || (p.version || "").toLowerCase().includes(f));
      }

      if (!products.length) {
        tableEl.innerHTML = `<div class="empty-state"><p>No products found</p></div>`;
        pagEl.innerHTML = "";
        return;
      }

      tableEl.innerHTML = `
        <table>
          <thead><tr><th>Product</th><th>Version</th><th>Packages</th><th>Files</th></tr></thead>
          <tbody>
            ${products.map(p => `
              <tr>
                <td><a href="#/products/${encodeURIComponent(p.name)}/${encodeURIComponent(p.version)}" class="product-link">${esc(p.name)}</a></td>
                <td class="mono">${esc(p.version)}</td>
                <td>${App.fmt(p.total_packages)}</td>
                <td>${App.fmt(p.total_files)}</td>
              </tr>`).join("")}
          </tbody>
        </table>`;

      const total = data.total || products.length;
      const page = Math.floor(s.offset / s.limit) + 1;
      const pages = Math.ceil(total / s.limit);
      pagEl.innerHTML = `
        <button class="btn-ghost btn-sm" ${s.offset === 0 ? "disabled" : ""} id="prev-page">Prev</button>
        <span>Page ${page} of ${pages} (${App.fmt(total)} total)</span>
        <button class="btn-ghost btn-sm" ${s.offset + s.limit >= total ? "disabled" : ""} id="next-page">Next</button>`;

      document.getElementById("prev-page")?.addEventListener("click", () => {
        s.offset = Math.max(0, s.offset - s.limit);
        this.load();
      });
      document.getElementById("next-page")?.addEventListener("click", () => {
        s.offset += s.limit;
        this.load();
      });
    } catch (e) {
      if (e.message !== "__auth__") {
        tableEl.innerHTML = `<div class="alert alert-error">${e.message}</div>`;
      }
    }
  },
};

function esc(s) {
  if (!s) return "";
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}
