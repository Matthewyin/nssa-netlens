import React from 'react';
import './SearchBar.css';

const SearchBar = ({ value, onChange, placeholder = "Search..." }) => {
  return (
    <div className="search-bar-container">
      <span className="search-icon">🔍</span>
      <input
        type="text"
        className="search-input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
      {value && (
        <button className="search-clear" onClick={() => onChange('')}>
          ×
        </button>
      )}
    </div>
  );
};

export default SearchBar;
