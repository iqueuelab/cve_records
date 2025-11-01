import { useCallback, useEffect, useState } from "react";
import "./CVEList.css";

const API_BASE = "/api/cve-history/"; // change to full URL if needed

function buildQuery(params) {
  const esc = encodeURIComponent;
  return Object.keys(params)
    .filter(
      (k) => params[k] !== undefined && params[k] !== null && params[k] !== ""
    )
    .map((k) => esc(k) + "=" + esc(params[k]))
    .join("&");
}

export default function CVEList() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);
  const [count, setCount] = useState(0);
  const [sort, setSort] = useState("-created");
  const [filters, setFilters] = useState({ q: "", cveId: "", eventName: "" });

  const fetchPage = useCallback(
    async (p = page, ps = pageSize, s = sort, f = filters) => {
      setLoading(true);
      try {
        const params = { page: p, page_size: ps, sort: s };
        // include simple filters
        if (f.q) params.q = f.q;
        if (f.cveId) params.cveId = f.cveId;
        if (f.eventName) params.eventName = f.eventName;

        const url = API_BASE + "?" + buildQuery(params);
        const resp = await fetch(url);
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const data = await resp.json();
        setItems(data.results || []);
        setCount(data.count || 0);
        setPage(p);
      } catch (e) {
        console.error(e);
        alert("Failed to fetch data: " + e.message);
      } finally {
        setLoading(false);
      }
    },
    [page, pageSize, sort, filters]
  );

  useEffect(() => {
    fetchPage(1);
  }, [fetchPage]);

  const onSort = (field) => {
    let dir = "-"; // default desc
    if (sort.replace("-", "") === field) {
      // toggle
      dir = sort.startsWith("-") ? "" : "-";
    }
    setSort(dir + field);
    fetchPage(1, pageSize, dir + field, filters);
  };

  const onFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters((prev) => ({ ...prev, [name]: value }));
  };

  const applyFilters = () => fetchPage(1, pageSize, sort, filters);

  const totalPages = Math.ceil(count / pageSize) || 1;

  return (
    <div>
      <div className="controls">
        <div className="filters">
          <input
            name="q"
            placeholder="Search (q)"
            value={filters.q}
            onChange={onFilterChange}
          />
          <input
            name="cveId"
            placeholder="CVE ID"
            value={filters.cveId}
            onChange={onFilterChange}
          />
          <input
            name="eventName"
            placeholder="Event name"
            value={filters.eventName}
            onChange={onFilterChange}
          />
          <button onClick={applyFilters}>Apply</button>
        </div>
        <div className="page-controls">
          <label>
            Page size:
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                fetchPage(1, Number(e.target.value));
              }}
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </label>
        </div>
      </div>

      <table className="cve-table">
        <thead>
          <tr>
            <th onClick={() => onSort("cveId")}>CVE ID</th>
            <th onClick={() => onSort("eventName")}>Event</th>
            <th onClick={() => onSort("cve_change_id")}>Change ID</th>
            <th onClick={() => onSort("source_identifier")}>Source</th>
            <th onClick={() => onSort("created")}>Created</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr>
              <td colSpan={6}>Loading...</td>
            </tr>
          ) : items.length === 0 ? (
            <tr>
              <td colSpan={6}>No records</td>
            </tr>
          ) : (
            items.map((it) => (
              <tr key={it.id}>
                <td>{it.cveId}</td>
                <td>{it.eventName}</td>
                <td>{it.cveChangeId}</td>
                <td>{it.sourceIdentifier}</td>
                <td>{it.created}</td>
                <td>
                  <pre className="small">
                    {JSON.stringify(it.details || it.raw || {}, null, 2)}
                  </pre>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>

      <div className="pagination">
        <button onClick={() => fetchPage(1)} disabled={page === 1}>
          First
        </button>
        <button onClick={() => fetchPage(page - 1)} disabled={page <= 1}>
          Prev
        </button>
        <span>
          Page {page} / {totalPages}
        </span>
        <button
          onClick={() => fetchPage(page + 1)}
          disabled={page >= totalPages}
        >
          Next
        </button>
        <button
          onClick={() => fetchPage(totalPages)}
          disabled={page >= totalPages}
        >
          Last
        </button>
      </div>
    </div>
  );
}
