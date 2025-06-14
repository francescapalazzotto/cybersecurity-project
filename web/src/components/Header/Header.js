import React from 'react';
import './Header.css';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFileCode, faUnlock, faChartLine, faFingerprint } from '@fortawesome/free-solid-svg-icons';

/**
 * Componente Header per la navigazione principale dell'applicazione.
 * @param {object} props - Le proprietà del componente.
 * @param {function} props.onNavigate - Funzione di callback per la navigazione tra le sezioni.
 */
function Header({ onNavigate }) {
  return (
    <header className="app-header">
      <div className="logo">
        <FontAwesomeIcon icon={faFingerprint} className="logo-icon" /> 
        <span>AEAD Platform</span>
      </div>
      <nav className="main-nav">
        <ul>
          <li>
            <a href="#encrypt" onClick={() => onNavigate('encrypt')}>
              <FontAwesomeIcon icon={faFileCode} className="nav-icon" /> 
              Criptazione
            </a>
          </li>
          <li>
            <a href="#decrypt" onClick={() => onNavigate('decrypt')}>
              <FontAwesomeIcon icon={faUnlock} className="nav-icon" /> 
              Decriptazione
            </a>
          </li>
          <li>
            <a href="#benchmark" onClick={() => onNavigate('benchmark')}>
              <FontAwesomeIcon icon={faChartLine} className="nav-icon" /> 
              Benchmark
            </a>
          </li>
        </ul>
      </nav>
    </header>
  );
}

export default Header;
