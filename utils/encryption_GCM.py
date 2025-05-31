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
    output_file_path: str,
    password: str,
    associated_data: bytes = None, # type: ignore
) -> None:
    '''
    Funzione che cripta un file utilizzando AES-GCM e salva il contenuto criptato.
    Il salt e il nonce vengono generati casualmente e salvati all'inizio del file criptato.

    Parametri:
        - file_path (str): path del file da criptare (plaintext).
        - output_file_path (str): path dove salvare il file criptato.
        - password (str): password dell'utente da cui verrà derivata la chiave.
        - associated_data (bytes): default None - dati aggiuntivi associati
          al file che non vengono criptati ma solamente autenticati.
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
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    # 6. Salvataggio nel file: [SALT] [NONCE] [CIPHERTEXT + TAG]
    with open(output_file_path, 'wb') as output_file:
        output_file.write(salt)
        output_file.write(nonce)
        output_file.write(ciphertext_with_tag)
    
    print(f"File '{file_path}' criptato e salvato in '{output_file_path}'")

def decrypt_file_GCM(
    file_path: str,
    output_file_path: str,
    password: str,
    associated_data: bytes = None, # type: ignore
) -> None:
    '''
    Funzione che decripta un file criptato con AES-GCM e salva il contenuto in plaintext.
    Il salt e il nonce vengono letti dall'inizio del file criptato.

    Parametri:
        - file_path (str): path del file criptato.
        - output_file_path (str): path dove salvare il file decriptato.
        - password (str): password dell'utente per derivare la chiave.
        - associated_data (bytes): default None - dati aggiuntivi associati
          al file (devono corrispondere a quelli usati in criptazione).
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
    key = derive_key_from_password(password, salt) # key ora è direttamente bytes
    
    aesgcm = AESGCM(key) # Non più key[0]
    
    try:
        plaintext = aesgcm.decrypt(
            nonce, 
            ciphertext_with_tag, 
            associated_data
        )

        with open(output_file_path, 'wb') as f:
            f.write(plaintext)
        print(f"File '{file_path}' decriptato e salvato in '{output_file_path}'")
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
    input_filename = "docs/GCM_input.txt"
    with open(input_filename, "w") as f:
        f.write("Questo è il contenuto del mio documento sensibile.\n")
        f.write("Queste informazioni devono rimanere confidenziali e integre.\n")

    # --- PASSWORD DELL'UTENTE (simulata) ---
    user_password = "LaMiaPasswordMoltoSicuraPerIlMioProgetto!" 

    # Associated Data per l'esempio
    file_metadata_aad = b"file_type:document_sensitive;original_name:GCM_input.txt"

    output_encrypted_filename = "docs/GCM_output_encrypt.enc"
    output_decrypted_filename = "docs/GCM_output_decrypt.txt"

    print('******* INIZIO CRIPTAGGIO GCM *******')
    print()
    try:
        encrypt_file_GCM(
            file_path=input_filename,
            output_file_path=output_encrypted_filename,
            password=user_password, # Passa solo la password
            associated_data=file_metadata_aad
        )
        print("Criptaggio AES-GCM riuscito.")
    except Exception as e:
        print(f"Criptaggio GCM fallito: {e}.")

    print('\n******* INIZIO DECRIPTAGGIO GCM *******')
    print()
    try:
        decrypt_file_GCM(
            file_path=output_encrypted_filename,
            output_file_path=output_decrypted_filename,
            password=user_password, # Passa solo la password
            associated_data=file_metadata_aad
        )
        print("Decriptaggio AES-GCM riuscito.")
    except InvalidTag:
        print("Decriptaggio AES-GCM fallito: tag non valido (file manomesso o password errata).")
    except Exception as e:
        print(f"Decriptaggio AES-GCM fallito: {e}.")
    
    print('\n******* FINE ESEMPIO GCM *******')

    # --- Test con password sbagliata per la decrittografia ---
    print('\n******* TEST: DECRIPTAGGIO GCM CON PASSWORD ERRATA *******')
    wrong_password = "UnaPasswordTotalmenteDiversa"
    try:
        decrypt_file_GCM(
            file_path=output_encrypted_filename,
            output_file_path="docs/GCM_output_decrypt_wrong_password.txt",
            password=wrong_password, # Password errata
            associated_data=file_metadata_aad
        )
    except InvalidTag:
        print("TEST SUPERATO: Decriptaggio GCM con password errata ha correttamente sollevato InvalidTag.")
    except Exception as e:
        print(f"TEST FALLITO: Decriptaggio GCM con password errata ha sollevato un errore inatteso: {e}.")

    # --- Test con AAD sbagliato per la decrittografia ---
    print('\n******* TEST: DECRIPTAGGIO GCM CON AAD ERRATO *******')
    wrong_aad = b"AnotherDocumentName"
    try:
        decrypt_file_GCM(
            file_path=output_encrypted_filename,
            output_file_path="docs/GCM_output_decrypt_wrong_aad.txt",
            password=user_password,
            associated_data=wrong_aad
        )
    except InvalidTag:
        print("TEST SUPERATO: Decriptaggio GCM con AAD errato ha correttamente sollevato InvalidTag.")
    except Exception as e:
        print(f"TEST FALLITO: Decriptaggio GCM con AAD errato ha sollevato un errore inatteso: {e}.")