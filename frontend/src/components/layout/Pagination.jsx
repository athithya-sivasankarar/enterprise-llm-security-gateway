import React from 'react';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';

export default function Pagination({
  currentPage,
  totalItems,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [10, 25, 50, 100]
}) {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const startItem = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endItem = Math.min(totalItems, currentPage * pageSize);

  return (
    <div className="pagination-wrapper">
      <div className="pagination-info">
        Showing <span className="font-mono font-semibold">{startItem}</span> to{' '}
        <span className="font-mono font-semibold">{endItem}</span> of{' '}
        <span className="font-mono font-semibold">{totalItems}</span> records
      </div>

      <div className="pagination-controls">
        {onPageSizeChange && (
          <div className="pagination-page-size">
            <span>Per page:</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              className="page-size-select"
            >
              {pageSizeOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="pagination-nav-buttons">
          <button
            className="btn-page-nav"
            onClick={() => onPageChange(1)}
            disabled={currentPage <= 1}
            title="First Page"
          >
            <ChevronsLeft size={15} />
          </button>
          <button
            className="btn-page-nav"
            onClick={() => onPageChange(currentPage - 1)}
            disabled={currentPage <= 1}
            title="Previous Page"
          >
            <ChevronLeft size={15} />
          </button>

          <span className="pagination-current-state">
            Page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
          </span>

          <button
            className="btn-page-nav"
            onClick={() => onPageChange(currentPage + 1)}
            disabled={currentPage >= totalPages}
            title="Next Page"
          >
            <ChevronRight size={15} />
          </button>
          <button
            className="btn-page-nav"
            onClick={() => onPageChange(totalPages)}
            disabled={currentPage >= totalPages}
            title="Last Page"
          >
            <ChevronsRight size={15} />
          </button>
        </div>
      </div>
    </div>
  );
}
