import os
import base64
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding # Importante: importa il modulo padding

# Struttura dei dati nel file criptato per EtM:
# [SALT (16 byte)] [IV (16 byte per AES-CBC)] [HMAC TAG (32 byte per SHA256)] [CIPHERTEXT (variabile)]

#*
#* CONSTANTS
#*
SALT_BYTES_LENGTH = 16      # Lunghezza standard per il salt di PBKDF2
KEY_LENGTH_AES_256 = 32     # Lunghezza della chiave AES a 256 bit (in bytes)
KDF_ITERATIONS = 100000     # Numero di iterazioni per PBKDF2 (raccomandato 100.000+)
BLOCK_SIZE_BITS = 128       # Dimensione del blocco per AES in bit (128 bit = 16 byte) - Usato per il padding PKCS7

# Specifiche per AES-CBC
IV_BYTES_LENGTH_CBC = 16    # IV per AES-CBC è sempre 16 byte (dimensione del blocco AES)

# Specifiche per HMAC-SHA256
HMAC_TAG_LENGTH_SHA256 = 32 # HMAC-SHA256 produce un output di 32 byte (256 bit)

#*
#* KEY MANAGEMENT FUNCTIONS
#*

def derive_keys_from_password_etm(password: str, salt: bytes) -> tuple[bytes, bytes]:
    '''
    Funzione che deriva due chiavi crittografiche distinte (una per Encryption, una per MAC)
    dalla password utilizzando PBKDF2HMAC.

    Parametri:
        - password (str): password dell'utente.
        - salt (bytes): sequenza casuale (salt) per la derivazione della chiave.
        Deve essere lo stesso per derivare le chiavi.
    
    Ritorna:
        - tuple[bytes, bytes]: una tupla contenente (encryption_key, mac_key).
        Entrambe le chiavi saranno di KEY_LENGTH_AES_256 (32 byte).
    '''
    # Conversione password in bytes
    pass_bytes = password.encode('utf-8')

    # Deriviamo una chiave master più lunga che poi divideremo in due chiavi indipendenti.
    # Questo è un modo sicuro per ottenere chiavi separate da una singola sorgente.
    master_kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = KEY_LENGTH_AES_256 * 2, # Abbiamo bisogno di 2 chiavi da 32 byte (una per encrypt, una per MAC)
        salt = salt,
        iterations = KDF_ITERATIONS,
        backend = default_backend()
    )
    master_key = master_kdf.derive(pass_bytes)

    # Dividiamo la chiave master in chiave di cifratura e chiave MAC
    encryption_key = master_key[:KEY_LENGTH_AES_256]
    mac_key = master_key[KEY_LENGTH_AES_256:]

    return encryption_key, mac_key

#*
#* AUTHENTICATED ENCRYPTION FUNCTIONS (Encrypt-then-MAC EtM)
#*

def encrypt_file_EtM(
    file_path: str,
    output_file_path: str,
    password: str,
    associated_data: bytes = None, # type: ignore
) -> None:
    '''
    Funzione che cripta un file utilizzando AES-CBC e autentica con HMAC-SHA256 (EtM).
    Il salt, IV e HMAC Tag vengono generati casualmente e salvati all'inizio del file criptato.

    Parametri:
        - file_path (str): path del file da criptare (plaintext).
        - output_file_path (str): path dove salvare il file criptato.
        - password (str): password dell'utente da cui verranno derivate le chiavi.
        - associated_data (bytes): default None - dati aggiuntivi associati
          al file che non vengono criptati ma solamente autenticati.
    '''
    # 1. Genera un nuovo salt casuale per questa operazione
    salt = os.urandom(SALT_BYTES_LENGTH)
    
    # 2. Deriva le chiavi di cifratura e MAC dalla password e dal salt
    encryption_key, mac_key = derive_keys_from_password_etm(password, salt)
    
    # 3. Genera un IV casuale e unico per AES-CBC
    iv = os.urandom(IV_BYTES_LENGTH_CBC) # IV per CBC ha la stessa dimensione del blocco (16 byte per AES)
    
    # 4. Leggi il contenuto del file (plaintext)
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    
    #* Passo di Cifratura (AES-CBC)
    # Applica il padding al plaintext prima della cifratura.
    # PKCS7 è lo schema di padding standard per AES.
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Inizializza il cifratore con AES e modalità CBC
    cipher = Cipher(
        algorithms.AES(encryption_key), 
        modes.CBC(iv), 
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()

    # Cifra il plaintext con padding
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    #* Passo di Autenticazione (HMAC-SHA256)
    # Calcola l'HMAC su IV + AAD (se presente) + CIPHERTEXT
    # È fondamentale includere l'IV e l'AAD per autenticare tutti i dati che 
    # influiscono sulla decrittografia e che non sono segreti.
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv) # Autentica l'IV
    if associated_data:
        h.update(associated_data) # Autentica l'AAD
    h.update(ciphertext) # Autentica il ciphertext
    hmac_tag = h.finalize()

    # 5. Salvataggio nel file: [SALT] [IV] [HMAC_TAG] [CIPHERTEXT]
    with open(output_file_path, 'wb') as output_file:
        output_file.write(salt)
        output_file.write(iv)
        output_file.write(hmac_tag)
        output_file.write(ciphertext) # Questo è il ciphertext con padding
    
    print(f"File '{file_path}' criptato (EtM) e salvato in '{output_file_path}'")

def decrypt_file_EtM(
    file_path: str,
    output_file_path: str,
    password: str,
    associated_data: bytes = None, # type: ignore
) -> None:
    '''
    Funzione che decripta un file criptato con AES-CBC e verifica l'autenticità 
    con HMAC-SHA256 (EtM).
    Il salt, IV e HMAC Tag vengono letti dall'inizio del file criptato.

    Parametri:
        - file_path (str): path del file criptato.
        - output_file_path (str): path dove salvare il file decriptato.
        - password (str): password dell'utente per derivare le chiavi.
        - associated_data (bytes): default None - dati aggiuntivi associati
          al file (devono corrispondere a quelli usati in criptazione).
    '''
    with open(file_path, 'rb') as file:
        # 1. Leggi il salt dal file
        salt = file.read(SALT_BYTES_LENGTH)
        if len(salt) < SALT_BYTES_LENGTH:
            raise ValueError(f"File '{file_path}' è troppo piccolo o corrotto: impossibile leggere il salt ({SALT_BYTES_LENGTH} byte).")
        
        # 2. Leggi l'IV subito dopo il salt
        iv = file.read(IV_BYTES_LENGTH_CBC)
        if len(iv) < IV_BYTES_LENGTH_CBC:
            raise ValueError(f"File '{file_path}' è troppo piccolo o corrotto: impossibile leggere l'IV ({IV_BYTES_LENGTH_CBC} byte).")
        
        # 3. Leggi l'HMAC Tag successivo
        received_hmac_tag = file.read(HMAC_TAG_LENGTH_SHA256)
        if len(received_hmac_tag) < HMAC_TAG_LENGTH_SHA256:
            raise ValueError(f"File '{file_path}' è troppo piccolo o corrotto: impossibile leggere l'HMAC tag ({HMAC_TAG_LENGTH_SHA256} byte).")
        
        # 4. Leggi il resto come ciphertext
        ciphertext = file.read()

    # 5. Deriva le chiavi di cifratura e MAC dalla password e dal salt letto dal file
    encryption_key, mac_key = derive_keys_from_password_etm(password, salt)

    #* Passo di Autenticazione (verifica HMAC)
    # Ricalcola l'HMAC usando gli stessi dati (IV + AAD + Ciphertext) e la chiave MAC derivata.
    # Questo passo DEVE avvenire PRIMA della decifratura per garantire EtM.
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    if associated_data:
        h.update(associated_data)
    h.update(ciphertext) # Calcola l'HMAC sul ciphertext ricevuto
    
    try:
        h.verify(received_hmac_tag) # Compara l'HMAC ricalcolato con quello letto dal file
        print("Verifica HMAC riuscita: i dati non sono stati manomessi.")
    except InvalidTag:
        # Se la verifica fallisce, i dati sono stati manomessi o la password/chiave/AAD è errata.
        print(f"ERRORE: La verifica HMAC è fallita per '{file_path}'. I dati potrebbero essere stati manomessi, la password è errata o l'AAD non corrisponde.")
        raise InvalidTag("HMAC verification failed. Data tampered, wrong password/keys, or AAD mismatch.")

    #* Passo di Decifratura (AES-CBC)
    # Procede alla decifratura SOLO SE la verifica HMAC è riuscita.
    cipher = Cipher(
        algorithms.AES(encryption_key), 
        modes.CBC(iv), 
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()

    # Decifra il ciphertext per ottenere il plaintext con padding
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Rimuovi il padding dal plaintext decifrato
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
    print(f"File '{file_path}' decriptato (EtM) e salvato in '{output_file_path}'")

#*
#* EXAMPLE USAGE
#*

if __name__ == '__main__':
    # Creazione della directory 'docs' se non esiste
    if not os.path.exists('docs'):
        os.makedirs('docs')

    # Creazione di un file di input di esempio per EtM
    input_filename_etm = "docs/EtM_input.txt"
    with open(input_filename_etm, "w") as f:
        f.write("Questo è il contenuto del mio documento sensibile per il test EtM.\n")
        f.write("Queste informazioni devono rimanere confidenziali e integre.\n")
        f.write("A differenza di GCM, qui usiamo AES-CBC + HMAC-SHA256.\n")
        f.write("Questo testo è un po' più lungo per testare il padding correttamente.\n" * 5) # Test con più testo

    # --- PASSWORD DELL'UTENTE (simulata per il test) ---
    user_password_etm = "LaMiaPasswordEtMSecreta!" 

    # Associated Data per l'esempio (deve essere identico in criptazione e decriptazione)
    file_metadata_aad_etm = b"file_type:etm_document_version_1.0;original_name:EtM_input.txt"

    output_encrypted_filename_etm = "docs/EtM_output_encrypt.enc"
    output_decrypted_filename_etm = "docs/EtM_output_decrypt.txt"

    print('\n\n******* INIZIO CRIPTAGGIO Encrypt-then-MAC (EtM) *******')
    print()
    try:
        encrypt_file_EtM(
            file_path=input_filename_etm,
            output_file_path=output_encrypted_filename_etm,
            password=user_password_etm,
            associated_data=file_metadata_aad_etm
        )
        print("Criptaggio EtM riuscito.")
    except Exception as e:
        print(f"Criptaggio EtM fallito: {e}.")

    print('\n******* INIZIO DECRIPTAGGIO Encrypt-then-MAC (EtM) *******')
    print()
    try:
        decrypt_file_EtM(
            file_path=output_encrypted_filename_etm,
            output_file_path=output_decrypted_filename_etm,
            password=user_password_etm,
            associated_data=file_metadata_aad_etm
        )
        print("Decriptaggio EtM riuscito.")
    except InvalidTag:
        print("Decriptaggio EtM fallito: tag non valido (file manomesso o password/AAD errata).")
    except Exception as e:
        print(f"Decriptaggio EtM fallito: {e}.")
    
    print('\n******* FINE ESEMPIO EtM *******')

    #* Test con password sbagliata per la decrittografia EtM
    print('\n\n******* TEST: DECRIPTAGGIO EtM CON PASSWORD ERRATA *******')
    wrong_password_etm_test = "PasswordCompletamenteSbagliata"
    try:
        decrypt_file_EtM(
            file_path=output_encrypted_filename_etm,
            output_file_path="docs/EtM_output_decrypt_wrong_password.txt",
            password=wrong_password_etm_test, # Password errata
            associated_data=file_metadata_aad_etm
        )
    except InvalidTag:
        print("TEST SUPERATO: Decriptaggio EtM con password errata ha correttamente sollevato InvalidTag (dovuto a chiave MAC errata).")
    except Exception as e:
        print(f"TEST FALLITO: Decriptaggio EtM con password errata ha sollevato un errore inatteso: {e}.")

    #* Test con AAD sbagliato per la decrittografia EtM
    print('\n******* TEST: DECRIPTAGGIO EtM CON AAD ERRATO *******')
    wrong_aad_etm_test = b"wrong_aad_for_etm_document_mismatch"
    try:
        decrypt_file_EtM(
            file_path=output_encrypted_filename_etm,
            output_file_path="docs/EtM_output_decrypt_wrong_aad.txt",
            password=user_password_etm,
            associated_data=wrong_aad_etm_test # AAD errato
        )
    except InvalidTag:
        print("TEST SUPERATO: Decriptaggio EtM con AAD errato ha correttamente sollevato InvalidTag.")
    except Exception as e:
        print(f"TEST FALLITO: Decriptaggio EtM con AAD errato ha sollevato un errore inatteso: {e}.")

    #* Test con file criptato manomesso (simula modifica del ciphertext) 
    print('\n******* TEST: DECRIPTAGGIO EtM CON FILE MANOMESSO (CIPHERTEXT MODIFICATO) *******')
    temp_tampered_file = "docs/EtM_output_tampered.enc"
    try:
        with open(output_encrypted_filename_etm, 'rb') as f_orig:
            original_content = bytearray(f_orig.read())
        # Modifica un byte nel ciphertext (dopo salt, IV e HMAC tag)
        tamper_index = SALT_BYTES_LENGTH + IV_BYTES_LENGTH_CBC + HMAC_TAG_LENGTH_SHA256 + 5 # Cambia il 5° byte del ciphertext
        if len(original_content) > tamper_index:
            original_content[tamper_index] ^= 0x01 # Flippa un bit
            with open(temp_tampered_file, 'wb') as f_tamper:
                f_tamper.write(original_content)
            print(f"File '{temp_tampered_file}' creato con manomissione.")

            decrypt_file_EtM(
                file_path=temp_tampered_file,
                output_file_path="docs/EtM_output_decrypt_tampered.txt",
                password=user_password_etm,
                associated_data=file_metadata_aad_etm
            )
        else:
            print("File troppo corto per simulare manomissione nel ciphertext.")
    except InvalidTag:
        print("TEST SUPERATO: Decriptaggio EtM con file manomesso ha correttamente sollevato InvalidTag (dovuto a HMAC non corrispondente).")
    except Exception as e:
        print(f"TEST FALLITO: Decriptaggio EtM con file manomesso ha sollevato un errore inatteso: {e}.")
    finally:
        if os.path.exists(temp_tampered_file):
            os.remove(temp_tampered_file) # Pulisci il file temporaneo
