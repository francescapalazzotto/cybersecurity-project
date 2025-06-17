import { useState } from "react";
import Body from "./components/Body/Body";
import Footer from "./components/Footer/Footer";
import Header from "./components/Header/Header";
import ModaleCentro from "./components/ModaleCentro/ModaleCentro";
import FormEncrypt from "./components/FormEncrypt/FormEncrypt";
import CryptoService from "./services/cryptoService";
import FormDecrypt from "./components/FormDecrypt/FormDecrypt";
import ResultsBenchmark from "./components/ResultsBenchmark/ResultsBenchmark";

function App() {
  const [modalEncrypt, setModalEncrypt] = useState(false);
  const [modalDecrypt, setModalDecrypt] = useState(false);
  const [modalBench, setModalBench] = useState(false);
  const [isLoadingBenchmark, setIsLoadingBenchmark] = useState(false);
  const [stateEncrypt, setStateEncrypt] = useState({
    mode: 'gcm',
    associated_data: '',
  });
  const [stateDecrypt, setStateDecrypt] = useState({
    mode: 'gcm',
    associated_data: '',
  });
  const [benchmarkResults, setBenchmarkResults] = useState(null);
  const [benchmarkMessage, setBenchmarkMessage] = useState('');

  // Funzione per avviare la criptazione collegato all'API
  const handleEncryptConfirm = async () => {
    if (!stateEncrypt.file || !stateEncrypt.password || !stateEncrypt.mode) {
        alert("Per favore, compila tutti i campi obbligatori (file, modalità, password).");
        return;
    }

    try {
        // CryptoService.encryptFile ora ritorna il nome del file criptato scaricato
        const filename = await CryptoService.encryptFile( 
            stateEncrypt.file,
            stateEncrypt.password,
            stateEncrypt.mode,
            stateEncrypt.associated_data
        );
        alert(`Criptazione riuscita: file "${filename}" scaricato.`); // Messaggio aggiornato
        setModalEncrypt(false); // Chiudi la modale al successo
        // Pulisci il form
        setStateEncrypt({
            file: null,
            mode: 'gcm',
            password: '',
            associated_data: '',
        });
    } catch (error) {
        alert(`${error.message}`);
    }
  };

  // Funzione per avviare la decriptazione collegato all'API
  const handleDecryptConfirm = async () => {
    if (!stateDecrypt.file || !stateDecrypt.password || !stateDecrypt.mode) {
        alert("Per favore, compila tutti i campi obbligatori (file, modalità, password).");
        return;
    }

    try {
        // Chiama la tua funzione decryptFile dal servizio API
        const result = await CryptoService.decryptFile(
            stateDecrypt.file,
            stateDecrypt.password,
            stateDecrypt.mode,
            stateDecrypt.associated_data
        );
        alert(`Decriptazione riuscita: ${result}`);
        setModalDecrypt(false); // Chiudi la modale al successo
        // Pulisci il form se necessario
        setStateDecrypt({
            file: null,
            mode: 'gcm',
            password: '',
            associated_data: '',
        });
    } catch (error) {
        alert(`${error.message}`);
    }
  };

  // Funzione per avviare l'analisi di benchmark collegata all'API
  const handleBenchmarkConfirm = async () => {
    setIsLoadingBenchmark(true);
    setBenchmarkMessage('Esecuzione benchmark in corso... potrebbe richiedere del tempo.');
    setBenchmarkResults(null);

    try {
      const results = await CryptoService.runBenchmark();
      setBenchmarkResults(results); 
      setBenchmarkMessage('Benchmark completato!');
    } catch (error) {
      console.error('Errore durante il benchmark:', error);
      setBenchmarkMessage(`Errore durante il benchmark: ${error.message}`);
      setBenchmarkResults(null);
    } finally {
      setIsLoadingBenchmark(false);
    }
  };

  // Function per la gestione delle modali presenti per l'utilizzo delle funzioni
  const onNavigate = (type) => {
    if (type === 'encrypt') {
      setModalEncrypt(true);
    }
    if (type === 'decrypt') {
      setModalDecrypt(true);
    }
    if (type === 'benchmark') {
      setModalBench(true);
    }
  };

  // Function per gestire la compilazione dei form
  const onChange = (tipo, e) => {
    const { name, value, files, type } = e.target;
    if (tipo === 'encrypt') {
      setStateEncrypt((prevState) => ({
        ...prevState,
        [name]: type === 'file' ? files[0] : value,
      }));
    } else if (tipo === 'decrypt') {
      setStateDecrypt((prevState) => ({
        ...prevState,
        [name]: type === 'file' ? files[0] : value,
      }));
    }
  };
  console.log('DEC', stateDecrypt);
  console.log('ENC', stateEncrypt);
  return (
    <>
      <div className="App">
        <Header onNavigate={onNavigate}/>
        <Body />
        <Footer />
      </div>
      <ModaleCentro
        modalTitle="Criptazione File"
        modalBody={(
          <FormEncrypt
            stateEncrypt={stateEncrypt}
            onChange={onChange}
          />
        )}
        labelConfirm="Cripta File"
        onConfirm={() => handleEncryptConfirm()}
        onClose={() => setModalEncrypt(false)}
        show={modalEncrypt}
      />
      <ModaleCentro
        modalTitle="Decriptazione File"
        modalBody={(
          <FormDecrypt
            stateDecrypt={stateDecrypt}
            onChange={onChange}
          />
        )}
        labelConfirm="Decripta File"
        onConfirm={() => handleDecryptConfirm()}
        onClose={() => setModalDecrypt(false)}
        show={modalDecrypt}
      />
      <ModaleCentro
        modalTitle="Benchmark Performance"
        labelConfirm={isLoadingBenchmark ? 'Esecuzione...' : 'Avvia Benchmark'}
        onConfirm={handleBenchmarkConfirm}
        onClose={() => {
            setModalBench(false);
            setBenchmarkResults(null);
            setBenchmarkMessage('');
        }}
        show={modalBench}
        modalBody={(
          <ResultsBenchmark
            isLoadingBenchmark={isLoadingBenchmark}
            benchmarkMessage={benchmarkMessage}
            benchmarkResults={benchmarkResults}
          />
        )}
        disableConfirm={isLoadingBenchmark}
      />
    </>
  );
}

export default App;
