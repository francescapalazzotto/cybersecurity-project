import React from 'react';
import './Body.css';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faShieldHalved } from '@fortawesome/free-solid-svg-icons'; // Icona per la sicurezza
import neuralNetworkImage from '../../images/neural_network.jpeg';

/**
 * Componente Body per presentare la piattaforma AEAD.
 * Mostra un'immagine di sfondo, un titolo e una descrizione dell'Authenticated Encryption.
 * @param {object} props - Le proprietà del componente.
 */
function Body({ imageUrl }) {
  return (
    <section
      className="hero-section" 
      style={{
        backgroundImage: `url(${neuralNetworkImage})`,
        backgroundSize: 'cover',       
        backgroundPosition: 'center', 
        backgroundRepeat: 'no-repeat', 
      }}>
      <div className="hero-overlay">
        <div className="hero-content">
          <h1 className="platform-title">
            <FontAwesomeIcon icon={faShieldHalved} className="shield-icon" />
            AEAD Platform
          </h1>
          <p className="platform-description">
            La piattaforma offre un'implementazione robusta di <strong>Authenticated Encryption with Associated Data (AEAD)</strong>,
            garantendo non solo la <strong>confidenzialità</strong> dei tuoi dati attraverso algoritmi di cifratura avanzati (come AES-GCM e AES-CBC con HMAC),
            ma anche la loro <strong>integrità</strong> e <strong>autenticità</strong>.
            Questo significa che i tuoi file sono protetti sia da occhi indiscreti che da qualsiasi tentativo di manomissione.
            Scegli tra diverse modalità di cifratura e verifica le performance con il nostro strumento di benchmark integrato.
            La sicurezza dei tuoi dati è la nostra priorità.
          </p>
        </div>
      </div>
    </section>
  );
}

export default Body;
