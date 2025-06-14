const BACKEND_BASE_URL = 'http://127.0.0.1:8000';

/**
 * Funzione generica per gestire le risposte HTTP.
 * Se la risposta non è OK, solleva un errore con il dettaglio dal backend.
 */
const handleResponse = async (res) => {
    if (!res.ok) {
        // Tenta di leggere il dettaglio dell'errore dal JSON di FastAPI
        const errorData = await res.json();
        throw new Error(errorData.detail || `HTTP error! status: ${res.status}`);
    }
    return res;
};

/**
 * Cripta un file tramite l'API di backend e gestisce il download del file criptato.
 * @param {File} file - Il file da criptare (oggetto File).
 * @param {string} password - La password per la criptazione.
 * @param {string} mode - La modalità di cifratura ('gcm' o 'etm').
 * @param {string} associatedData - Dati associati (opzionale).
 * @returns {Promise<string>} - Promise che risolve con il nome del file criptato scaricato.
 */
export const encryptFile = async (file, password, mode, associatedData = '') => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('password', password);
    formData.append('mode', mode);
    formData.append('associated_data', associatedData);

    try {
        const response = await fetch(`${BACKEND_BASE_URL}/encrypt/`, {
            method: 'POST',
            body: formData,
        });
        const handledResponse = await handleResponse(response);

        // Il backend ora restituisce il file criptato direttamente come blob
        const blob = await handledResponse.blob();
        const contentDisposition = handledResponse.headers.get('Content-Disposition');
        const filenameMatch = contentDisposition && contentDisposition.match(/filename="(.+)"/);
        const filename = filenameMatch ? filenameMatch[1] : 'encrypted_file.enc';

        // Crea un URL per il blob e attiva il download
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);

        return filename; // Restituisce il nome del file criptato scaricato
    } catch (error) {
        console.error("Error in encryptFile service:", error);
        throw error;
    }
};

/**
 * Decripta un file tramite l'API di backend e gestisce il download.
 * @param {File} file - Il file criptato da decriptare (oggetto File).
 * @param {string} password - La password per la decriptazione.
 * @param {string} mode - La modalità di cifratura ('gcm' o 'etm').
 * @param {string} associatedData - Dati associati (opzionale, deve corrispondere a quello usato in criptazione).
 * @returns {Promise<string>} - Promise che risolve con il nome del file decriptato scaricato.
 */
export const decryptFile = async (file, password, mode, associatedData = '') => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('password', password);
    formData.append('mode', mode);
    formData.append('associated_data', associatedData); // FastAPI accetta stringa vuota per None

    try {
        const response = await fetch(`${BACKEND_BASE_URL}/decrypt/`, {
            method: 'POST',
            body: formData,
        });
        const handledResponse = await handleResponse(response);

        // Per la decriptazione, il backend restituisce un file direttamente.
        // Dobbiamo estrarre il nome del file dagli headers Content-Disposition.
        const blob = await handledResponse.blob();
        const contentDisposition = handledResponse.headers.get('Content-Disposition');
        const filenameMatch = contentDisposition && contentDisposition.match(/filename="(.+)"/);
        const filename = filenameMatch ? filenameMatch[1] : 'decrypted_file.txt';

        // Crea un URL per il blob e attiva il download
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url); // Libera l'URL dell'oggetto

        return filename; // Restituisce il nome del file scaricato
    } catch (error) {
        console.error("Error in decryptFile service:", error);
        throw error;
    }
};

/**
 * Esegue il benchmark delle performance criptografiche.
 * @returns {Promise<Array<Object>>} - Promise che risolve con un array di oggetti risultati benchmark.
 */
export const runBenchmark = async () => {
    try {
        const response = await fetch(`${BACKEND_BASE_URL}/benchmark/`);
        const handledResponse = await handleResponse(response);
        return handledResponse.json(); // Restituisce l'array JSON dei risultati
    } catch (error) {
        console.error("Error in runBenchmark service:", error);
        throw error;
    }
};

const CryptoService = {
    encryptFile,
    decryptFile,
    runBenchmark,
};

export default CryptoService;