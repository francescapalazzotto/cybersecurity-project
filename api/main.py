import os
import time
import io
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from cryptography.exceptions import InvalidTag

# Importa le tue funzioni crittografiche dal modulo dedicato
from crypto_utils import (
    encrypt_data_GCM, decrypt_data_GCM,
    encrypt_data_EtM, decrypt_data_EtM,
)

app = FastAPI()

# Configurazione CORS per permettere al frontend React di comunicare con backend Python
origins = [
    "http://localhost:3000", # L'URL del tuo frontend React
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Cartella di output per i file criptati/decriptati sul server
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "docs") # La cartella 'docs' sarà sempre relativa a main.py

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

@app.get("/")
async def read_root():
    return {"message": "Servizio di Criptazione AEAD attivo. Vai su /docs per la documentazione API (Swagger UI)."}

@app.post("/encrypt/")
async def encrypt_file(
    file: UploadFile = File(...),
    mode: str = Form(...),
    password: str = Form(...),
    associated_data: str = Form(""), # Valore predefinito: stringa vuota
):
    """
    Cripta un file usando la modalità AES-GCM o EtM.
    Se associated_data non è fornito (stringa vuota), viene passato None alle funzioni crittografiche.
    Restituisce il file criptato come download.
    """
    try:
        plaintext_content = await file.read()
        
        # Gestione AAD: Se la stringa è vuota, passa None alla funzione crittografica.
        # Altrimenti, codifica la stringa AAD in bytes.
        aad_to_use = associated_data.encode('utf-8') if associated_data else None 

        if mode.lower() == "gcm":
            encrypted_content = encrypt_data_GCM(plaintext_content, password, aad_to_use)
        elif mode.lower() == "etm":
            encrypted_content = encrypt_data_EtM(plaintext_content, password, aad_to_use)
        else:
            raise HTTPException(status_code=400, detail="Modalità di cifratura non valida. Scegli 'GCM' o 'EtM'.")

        original_filename_base = os.path.splitext(file.filename)[0] if file.filename else "encrypted_file"
        output_filename = f"{original_filename_base}_{mode.lower()}.enc"
        output_file_path = os.path.join(OUTPUT_DIR, output_filename)

        # Salva il file criptato su disco
        with open(output_file_path, "wb") as f:
            f.write(encrypted_content)

        # Restituisce il file criptato come download
        return StreamingResponse(
            io.BytesIO(encrypted_content), # Passa i dati binari
            media_type="application/octet-stream", # Tipo MIME generico per download
            headers={"Content-Disposition": f"attachment; filename={output_filename}"} # Header per forzare il download
        )

    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Errore durante la criptazione: {e}")
        raise HTTPException(status_code=500, detail=f"Errore interno del server durante la criptazione: {e}")


@app.post("/decrypt/")
async def decrypt_file(
    file: UploadFile = File(...),
    mode: str = Form(...),
    password: str = Form(...),
    associated_data: str = Form(''),
):
    """
    Decripta un file criptato usando la modalità AES-GCM o EtM.
    """
    try:
        encrypted_content = await file.read()
        
        # Gestione AAD: Se la stringa è vuota, passa None alla funzione crittografica.
        # Altrimenti, codifica la stringa AAD in bytes.
        # L'AAD qui DEVE corrispondere esattamente a quello usato durante la criptazione.
        aad_to_use = associated_data.encode('utf-8') if associated_data else None
        
        if mode.lower() == "gcm":
            plaintext_content = decrypt_data_GCM(encrypted_content, password, aad_to_use)
        elif mode.lower() == "etm":
            plaintext_content = decrypt_data_EtM(encrypted_content, password, aad_to_use)
        else:
            raise HTTPException(status_code=400, detail="Modalità di decifratura non valida. Scegli 'GCM' o 'EtM'.")
        
        # Genera un nome per il file decriptato, cercando di ripristinare l'estensione originale
        # Questo è un esempio, in un'app reale potresti salvare l'estensione originale nell'AAD
        original_filename_base = os.path.splitext(file.filename)[0] if file.filename else "decrypted_file"
        # Rimuovi l'estensione .enc se presente
        if original_filename_base.endswith(".enc"):
            original_filename_base = os.path.splitext(original_filename_base)[0]
        
        output_filename = f"{original_filename_base}_decrypted.txt" # Estensione di default .txt
        output_file_path = os.path.join(OUTPUT_DIR, output_filename)

        with open(output_file_path, "wb") as f:
            f.write(plaintext_content)

        # Restituisce il file decriptato come download
        return StreamingResponse(
            io.BytesIO(plaintext_content),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={output_filename}"}
        )

    except InvalidTag:
        raise HTTPException(
            status_code=401, 
            detail="Verifica di autenticazione fallita: i dati sono stati manomessi, la password o l'AAD sono errati.",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Formato del file criptato non valido: {e}",
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Errore durante la decriptazione: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Errore interno del server durante la decriptazione: {e}",
        )

@app.get("/benchmark/")
async def run_benchmark():
    """
    Esegue un benchmark delle performance di criptazione e decriptazione per GCM ed EtM.
    Restituisce i tempi di esecuzione in JSON.
    """
    results = []
    
    # Crea la directory per i file di test se non esiste
    test_dir = os.path.join(OUTPUT_DIR, "benchmark_files")
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)

    # Dimensioni dei file da testare (in bytes)
    # 1KB, 10KB, 100KB, 1MB, 10MB, 100MB
    file_sizes = [
        1 * 1024,
        10 * 1024,
        100 * 1024,
        1 * 1024 * 1024,
        10 * 1024 * 1024,
        100 * 1024 * 1024,
    ]
    
    password = "benchmark_password"
    aad = b"benchmark_aad"
    num_iterations = 5 # Numero di ripetizioni per ogni test per mediare i tempi

    for size in file_sizes:
        print(f"Generazione file di test di {size / 1024} KB...")
        # Genera un file fittizio per il test
        # Assicurati che il contenuto sia riempito per evitare problemi di padding
        test_plaintext = os.urandom(size) # Dati casuali
        
        # Test GCM
        gcm_encrypt_times = []
        gcm_decrypt_times = []
        for _ in range(num_iterations):
            start = time.perf_counter()
            encrypted_gcm_data = encrypt_data_GCM(test_plaintext, password, aad)
            gcm_encrypt_times.append(time.perf_counter() - start)
            
            start = time.perf_counter()
            try:
                decrypt_data_GCM(encrypted_gcm_data, password, aad)
            except Exception as e:
                print(f"Errore decriptazione GCM durante benchmark: {e}")
                gcm_decrypt_times.append(float('inf')) # Segnala errore grave
                continue
            gcm_decrypt_times.append(time.perf_counter() - start)

        results.append({
            "mode": "GCM",
            "file_size_bytes": size,
            "file_size_kb": round(size / 1024, 2),
            "avg_encrypt_time_ms": round(sum(gcm_encrypt_times) / num_iterations * 1000, 4),
            "avg_decrypt_time_ms": round(sum(gcm_decrypt_times) / num_iterations * 1000, 4),
        })

        # Test EtM
        etm_encrypt_times = []
        etm_decrypt_times = []
        for _ in range(num_iterations):
            start = time.perf_counter()
            encrypted_etm_data = encrypt_data_EtM(test_plaintext, password, aad)
            etm_encrypt_times.append(time.perf_counter() - start)
            
            start = time.perf_counter()
            try:
                decrypt_data_EtM(encrypted_etm_data, password, aad)
            except Exception as e:
                print(f"Errore decriptazione EtM durante benchmark: {e}")
                etm_decrypt_times.append(float('inf')) # Segnala errore grave
                continue
            etm_decrypt_times.append(time.perf_counter() - start)

        results.append({
            "mode": "EtM",
            "file_size_bytes": size,
            "file_size_kb": round(size / 1024, 2),
            "avg_encrypt_time_ms": round(sum(etm_encrypt_times) / num_iterations * 1000, 4),
            "avg_decrypt_time_ms": round(sum(etm_decrypt_times) / num_iterations * 1000, 4),
        })

    return JSONResponse(content=results, status_code=200)

