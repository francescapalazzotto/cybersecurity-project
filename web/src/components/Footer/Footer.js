import React from 'react';
import './Footer.css';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCopyright, faUserGraduate, faBook } from '@fortawesome/free-solid-svg-icons';

/**
 * Componente Footer per visualizzare le informazioni sul creatore e sul corso.
 */
function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="app-footer">
      <div className="footer-content">
        <p>
          <FontAwesomeIcon icon={faCopyright} className="footer-icon" />
          {currentYear} {' '}
          Francesca Maria Palazzotto
        </p>
        <p>
          <FontAwesomeIcon icon={faUserGraduate} className="footer-icon" /> 
          Corso di Laurea: LM-18 Data, Algorithms and Machine Intelligence
        </p>
        <p>
          <FontAwesomeIcon icon={faBook} className="footer-icon" />
          Materia: Cybersecurity 
        </p>
      </div>
    </footer>
  );
}

export default Footer;
