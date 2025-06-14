import { faPlayCircle, faSpinner } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

function ResultsBenchmark({
    isLoadingBenchmark,
    benchmarkMessage,
    benchmarkResults,
}) {
  return (
    <div style={{ textAlign: 'center', minHeight: '150px' }}>
        {(!isLoadingBenchmark && !benchmarkMessage) && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '20px' }}>
                <FontAwesomeIcon icon={faPlayCircle} size="3x" style={{ marginBottom: '10px', color: '#333' }} /> {/* Icona più grande e grigia/nera */}
                <p style={{ fontSize: '1.2em', color: '#333', fontWeight: 'normal' }}> {/* Testo più grande, nero/grigio, normale */}
                    In questa sezione è possibile visualizzare i risultati della performance
                    dei due metodi di criptazione disponibili in base alle dimensioni
                    diverse di un file. Procedere per la visualizzazione attraverso
                    il bottone sottostante.
                </p>
            </div>
        )}
        {isLoadingBenchmark && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '20px' }}>
                <FontAwesomeIcon icon={faSpinner} spin size="3x" style={{ marginBottom: '10px', color: '#007bff' }} /> {/* Icona più grande e blu */}
                <p style={{ fontSize: '1.2em', color: '#007bff', fontWeight: 'bold' }}> {/* Testo più grande, blu e grassetto */}
                    {benchmarkMessage}
                </p>
            </div>
        )}
        {!isLoadingBenchmark && benchmarkMessage && <p>{benchmarkMessage}</p>}

        {benchmarkResults && (
            <div className="benchmark-results-modal">
                {/* Tabella per GCM */}
                <h3 style={{ marginTop: '20px', marginBottom: '10px', color: '#007bff' }}>Risultati GCM:</h3>
                <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '5px', marginBottom: '20px' }}>
                    <thead>
                        <tr style={{ background: '#e9ecef' }}>
                            <th style={{ padding: '8px', border: '1px solid #ddd' }}>Dimensione (KB)</th>
                            <th style={{ padding: '8px', border: '1px solid #ddd' }}>Criptazione (ms)</th>
                            <th style={{ padding: '8px', border: '1px solid #ddd' }}>Decriptazione (ms)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {benchmarkResults
                            .filter(result => result.mode.toLowerCase() === 'gcm')
                            .map((result, index) => (
                                <tr key={index} style={{ background: index % 2 === 0 ? '#f9f9f9' : 'white' }}>
                                    <td style={{ padding: '8px', border: '1px solid #ddd' }}>{result.file_size_kb}</td>
                                    <td style={{ padding: '8px', border: '1px solid #ddd' }}>{result.avg_encrypt_time_ms.toFixed(4)}</td>
                                    <td style={{ padding: '8px', border: '1px solid #ddd' }}>{result.avg_decrypt_time_ms.toFixed(4)}</td>
                                </tr>
                            ))}
                    </tbody>
                </table>

                {/* Tabella per EtM */}
                <h3 style={{ marginTop: '20px', marginBottom: '10px', color: '#28a745' }}>Risultati EtM:</h3>
                <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '5px' }}>
                    <thead>
                        <tr style={{ background: '#e9ecef' }}>
                            <th style={{ padding: '8px', border: '1px solid #ddd' }}>Dimensione (KB)</th>
                            <th style={{ padding: '8px', border: '1px solid #ddd' }}>Criptazione (ms)</th>
                            <th style={{ padding: '8px', border: '1px solid #ddd' }}>Decriptazione (ms)</th>
                        </tr>
                    </thead>
                    <tbody>
                        {benchmarkResults
                            .filter(result => result.mode.toLowerCase() === 'etm')
                            .map((result, index) => (
                                <tr key={index} style={{ background: index % 2 === 0 ? '#f9f9f9' : 'white' }}>
                                    <td style={{ padding: '8px', border: '1px solid #ddd' }}>{result.file_size_kb}</td>
                                    <td style={{ padding: '8px', border: '1px solid #ddd' }}>{result.avg_encrypt_time_ms.toFixed(4)}</td>
                                    <td style={{ padding: '8px', border: '1px solid #ddd' }}>{result.avg_decrypt_time_ms.toFixed(4)}</td>
                                </tr>
                            ))}
                    </tbody>
                </table>
            </div>
        )}
    </div>
  );
}

export default ResultsBenchmark;