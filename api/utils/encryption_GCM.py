import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Struttura dei dati nel file criptato:
# [SALT (16 byte)] [NONCE/IV (12 byte per GCM)] [CIPHERTEXT + AUTH_TAG (variabile)]

#*
#* CONSTANTS
#*

SALT_BYTES_LENGTH = 16      # Lunghezza standard per il salt di PBKDF2
NONCE_BYTES_LENGTH_GCM = 12 # Lunghezza raccomandata per il nonce di AES-GCM
KEY_LENGTH_AES_256 = 32     # Lunghezza della chiave AES a 256 bit (in bytes)
KDF_ITERATIONS = 100000     # Numero di iterazioni per PBKDF2
OUTPUT_DIR = "docs"         # Cartella di output predefinita per i file

#*
#* KEY MANAGEMENT FUNCTIONS
#*

def derive_key_from_password(
    password: str,
    salt: bytes
) -> bytes:
    '''
    Funzione che deriva una chiave crittografica dalla password utilizzando PBKDF2HMAC.
    Il salt è un input obbligatorio, in quanto letto o generato esternamente.

    Parametri:
        - password (str): password dell'utente.
        - salt (bytes): sequenza casuale (salt) per la derivazione della chiave.
    
    Ritorna:
        - bytes: la chiave derivata.
    '''
    # Conversione password in bytes
    pass_bytes = password.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = KEY_LENGTH_AES_256,
        salt = salt,
        iterations = KDF_ITERATIONS,
        backend = default_backend()
    )
    return kdf.derive(pass_bytes)

#*
#* AUTHENTICATED ENCRYPTION FUNCTIONS (AES-GCM)
#*

def encrypt_file_GCM(
    file_path: str,
    password: str,
    associated_data: bytes = None, # type: ignore
) -> str:
    '''
    Funzione che cripta un file utilizzando AES-GCM e salva il contenuto criptato.
    Il salt e il nonce vengono generati casualmente e salvati all'inizio del file criptato.

    Parametri:
        - file_path (str): path del file da criptare (plaintext).
        - password (str): password dell'utente da cui verrà derivata la chiave.
        - associated_data (bytes): default None - dati aggiuntivi associati
          al file che non vengono criptati ma solamente autenticati.

    Ritorna:
        - output_file_path (str): path del file generato dalla criptazione
    '''
    # 1. Genera un nuovo salt casuale per questa operazione di criptazione
    salt = os.urandom(SALT_BYTES_LENGTH)
    
    # 2. Deriva la chiave dalla password dell'utente e dal salt generato
    key = derive_key_from_password(password, salt) # Passa il salt obbligatorio
    
    # 3. Genera un Nonce/IV casuale e unico
    nonce = os.urandom(NONCE_BYTES_LENGTH_GCM)
    
    aesgcm = AESGCM(key)

    # 4. Lettura del contenuto del file in modalità binaria
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    
    # 5. Cifratura del plaintext e autenticazione dell'associated_data
    # Estrazione nome del file originale per generare il file di output
    original_filename = os.path.basename(file_path)
    # Creazione un nuovo nome con estensione .enc e salvalo nella cartella OUTPUT_DIR
    output_filename = f"{os.path.splitext(original_filename)[0]}.enc" # mantiene il nome base, cambia estensione
    output_file_path = os.path.join(OUTPUT_DIR, output_filename)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    # 6. Salvataggio nel file: [SALT] [NONCE] [CIPHERTEXT + TAG]
    with open(output_file_path, 'wb') as output_file:
        output_file.write(salt)
        output_file.write(nonce)
        output_file.write(ciphertext_with_tag)
    
    print(f"File '{file_path}' criptato e salvato in '{output_file_path}'")
    return output_file_path

def decrypt_file_GCM(
    file_path: str,
    password: str,
    associated_data: bytes = None, # type: ignore
) -> str:
    '''
    Funzione che decripta un file criptato con AES-GCM e salva il contenuto in plaintext.
    Il salt e il nonce vengono letti dall'inizio del file criptato.

    Parametri:
        - file_path (str): path del file criptato.
        - password (str): password dell'utente per derivare la chiave.
        - associated_data (bytes): default None - dati aggiuntivi associati
          al file (devono corrispondere a quelli usati in criptazione).

    Ritorna:
        - output_file_path (str): ritorna il percorso del file decriptato
    '''
    with open(file_path, 'rb') as file:
        # 1. Lettura del salt dall'inizio del file
        salt = file.read(SALT_BYTES_LENGTH)
        if len(salt) < SALT_BYTES_LENGTH:
            raise ValueError(f"File '{file_path}' è troppo piccolo o corrotto: impossibile leggere il salt ({SALT_BYTES_LENGTH} byte).")
        
        # 2. Lettura del nonce successivo al salt all'interno del file
        nonce = file.read(NONCE_BYTES_LENGTH_GCM)
        if len(nonce) < NONCE_BYTES_LENGTH_GCM:
            raise ValueError(f"File '{file_path}' è troppo piccolo o corrotto: impossibile leggere il nonce ({NONCE_BYTES_LENGTH_GCM} byte).")
        
        # 3. Lettura del resto del file come ciphertext + tag
        ciphertext_with_tag = file.read()
    
    # 4. Derivazione della chiave attraverso la password fornita dall'utente e il salt letto dal file
    key = derive_key_from_password(password, salt) 
    
    aesgcm = AESGCM(key) 
    
    try:
        plaintext = aesgcm.decrypt(
            nonce, 
            ciphertext_with_tag, 
            associated_data
        )

        # Costruisci il percorso del file di output per il decriptato
        original_encrypted_filename = os.path.basename(file_path)
        # Rimuove l'estensione .enc e aggiunge .txt (o la tua estensione originale)
        decrypted_filename = f"{os.path.splitext(original_encrypted_filename)[0]}.txt" 
        output_file_path = os.path.join(OUTPUT_DIR, decrypted_filename)

        with open(output_file_path, 'wb') as f:
            f.write(plaintext)
        print(f"File '{file_path}' decriptato e salvato in '{output_file_path}'")
        return output_file_path # Ritorna il percorso del file decriptato

    except InvalidTag:
        print(f"ERRORE: Impossibile decriptare '{file_path}'. Il tag di autenticazione non è valido. I dati potrebbero essere stati manomessi o la password è errata.")
        raise InvalidTag("Authentication tag is invalid. Data might be tampered or password is wrong.")
    except Exception as e:
        print(f"ERRORE: Si è verificato un errore inatteso durante la decrittografia: {e}")
        raise

#*
#* EXAMPLE USAGE
#*

if __name__ == '__main__':
    # Creazione della directory 'docs' se non esiste
    if not os.path.exists('docs'):
        os.makedirs('docs')

    # Creazione di un file di input di esempio
    input_filename = os.path.join(OUTPUT_DIR, "GCM_input.txt")
    with open(input_filename, "w") as f:
        f.write("Questo è il contenuto del mio documento sensibile.\n")
        f.write("Queste informazioni devono rimanere confidenziali e integre.\n")

    # --- PASSWORD DELL'UTENTE (simulata) ---
    user_password = "LaMiaPasswordMoltoSicuraPerIlMioProgetto!" 

    # Associated Data per l'esempio
    file_metadata_aad = b"file_type:document_sensitive;original_name:GCM_input.txt"

    print('\n\n******* INIZIO CRIPTAGGIO GCM *******')
    print()
    encrypted_file_path_gcm = None # Variabile per memorizzare il path generato
    try:
        encrypted_file_path_gcm = encrypt_file_GCM(
            file_path=input_filename, # Ora usiamo direttamente input_filename
            password=user_password,
            associated_data=file_metadata_aad,
        )
        print("Criptaggio GCM riuscito.")
    except Exception as e:
        print(f"Criptaggio GCM fallito: {e}.")

    if encrypted_file_path_gcm: # Esegui il decriptaggio solo se il criptaggio è riuscito
        print('\n******* INIZIO DECRIPTAGGIO GCM *******')
        print()
        try:
            decrypted_file_path_gcm = decrypt_file_GCM(
                file_path=encrypted_file_path_gcm, # Usiamo il path restituito dal criptaggio
                password=user_password,
                associated_data=file_metadata_aad,
            )
            print("Decriptaggio GCM riuscito.")
        except InvalidTag:
            print("Decriptaggio GCM fallito: tag non valido (file manomesso o password/AAD errata).")
        except Exception as e:
            print(f"Decriptaggio GCM fallito: {e}.")
    else:
        print("Decriptaggio GCM saltato a causa di errori nel criptaggio.")
    
    print('\n******* FINE ESEMPIO GCM *******')

    # --- Test con password sbagliata per la decrittografia ---
    print('\n******* TEST: DECRIPTAGGIO GCM CON PASSWORD ERRATA *******')
    wrong_password = "UnaPasswordTotalmenteDiversa"
    if encrypted_file_path_gcm: # Esegui il test solo se il file criptato esiste
        try:
            # Per i test falliti, potremmo voler creare un file di output temporaneo
            # o semplicemente omettere di salvare il risultato, dato che ci aspettiamo un errore.
            # Per coerenza, generiamo comunque un path per l'output.
            temp_output_wrong_password = os.path.join(
                OUTPUT_DIR, 
                f"GCM_output_decrypt_wrong_password_{os.path.basename(encrypted_file_path_gcm).replace('.enc', '')}.txt"
            )
            decrypt_file_GCM(
                file_path=encrypted_file_path_gcm,
                password=wrong_password, # Password errata
                associated_data=file_metadata_aad
            )
        except InvalidTag:
            print("TEST SUPERATO: Decriptaggio GCM con password errata ha correttamente sollevato InvalidTag.")
        except Exception as e:
            print(f"TEST FALLITO: Decriptaggio GCM con password errata ha sollevato un errore inatteso: {e}.")
    else:
        print("TEST SALTATO: File criptato non disponibile per il test della password errata.")

    # --- Test con AAD sbagliato per la decrittografia ---
    print('\n******* TEST: DECRIPTAGGIO GCM CON AAD ERRATO *******')
    wrong_aad = b"AnotherDocumentName"
    if encrypted_file_path_gcm: # Esegui il test solo se il file criptato esiste
        try:
            temp_output_wrong_aad = os.path.join(
                OUTPUT_DIR, 
                f"GCM_output_decrypt_wrong_aad_{os.path.basename(encrypted_file_path_gcm).replace('.enc', '')}.txt"
            )
            decrypt_file_GCM(
                file_path=encrypted_file_path_gcm,
                password=user_password,
                associated_data=wrong_aad # AAD errato
            )
        except InvalidTag:
            print("TEST SUPERATO: Decriptaggio GCM con AAD errato ha correttamente sollevato InvalidTag.")
        except Exception as e:
            print(f"TEST FALLITO: Decriptaggio GCM con AAD errato ha sollevato un errore inatteso: {e}.")
    else:
        print("TEST SALTATO: File criptato non disponibile per il test dell'AAD errato.")
