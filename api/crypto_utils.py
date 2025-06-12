import os
import base64
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

#*
#* CONSTANTS
#*
SALT_BYTES_LENGTH = 16
NONCE_BYTES_LENGTH_GCM = 12 # Standard per GCM
TAG_BYTES_LENGTH_GCM = 16   # Standard per GCM

# Specifiche per AES-CBC
IV_BYTES_LENGTH_CBC = 16    # IV per AES-CBC è sempre 16 byte (dimensione del blocco AES)
BLOCK_SIZE_BITS = 128       # Dimensione del blocco per AES in bit (128 bit = 16 byte) - Usato per il padding PKCS7
HMAC_TAG_LENGTH_SHA256 = 32 # HMAC-SHA256 produce un output di 32 byte (256 bit)

KEY_LENGTH_AES_256 = 32     # Lunghezza della chiave AES a 256 bit (in bytes)
KDF_ITERATIONS = 100000     # Numero di iterazioni per PBKDF2 (raccomandato 100.000+)

#*
#* KEY MANAGEMENT FUNCTIONS
#*

def derive_key_from_password_gcm(
    password: str,
    salt: bytes,
) -> bytes:
    '''
    Deriva una singola chiave crittografica dalla password utilizzando PBKDF2HMAC.

    Parametri:
        - password (str): password dell'utente.
        - salt (bytes): sequenza casuale (salt) per la derivazione della chiave.
    
    Ritorna:
        - bytes: la chiave derivata (KEY_LENGTH_AES_256).
    '''
    # Conversione password in bytes
    pass_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH_AES_256,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(pass_bytes)

def derive_keys_from_password_etm(
    password: str,
    salt: bytes,
) -> tuple[bytes, bytes]:
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
#* AUTHENTICATED ENCRYPTION FUNCTIONS (AES-GCM)
#*

def encrypt_data_GCM(
    plaintext_data: bytes,
    password: str,
    associated_data: bytes | None = None, 
) -> bytes:
    '''
    Cripta dati utilizzando AES-256-GCM.
    Il salt, nonce e tag vengono generati casualmente e inclusi nel ciphertext.

    Parametri:
        - plaintext_data (bytes): dati da criptare.
        - password (str): password dell'utente.
        - associated_data (bytes): dati aggiuntivi da autenticare ma non criptare.
    
    Ritorna:
        - bytes: il ciphertext risultante, concatenato come [SALT][NONCE][TAG][CIPHERTEXT].
    '''
    # 1. Genera un nuovo salt casuale per questa operazione di criptazione
    salt = os.urandom(SALT_BYTES_LENGTH)
    # 2. Deriva la chiave dalla password dell'utente e dal salt generato
    key = derive_key_from_password_gcm(password, salt) # Passa il salt obbligatorio
    # 3. Genera un Nonce/IV casuale e unico
    nonce = os.urandom(NONCE_BYTES_LENGTH_GCM)

    # Inizializza il cifratore GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    if associated_data is not None:
        encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext_data) + encryptor.finalize()
    tag = encryptor.tag

    # Concatena salt, nonce, tag e ciphertext per il file di output
    encrypted_data = salt + nonce + tag + ciphertext
    return encrypted_data

def decrypt_data_GCM(
    encrypted_data: bytes,
    password: str,
    associated_data: bytes | None = None,
) -> bytes:
    '''
    Decripta dati criptati con AES-256-GCM.
    Estrae salt, nonce e tag dai dati criptati.

    Parametri:
        - encrypted_data (bytes): dati criptati (in formato [SALT][NONCE][TAG][CIPHERTEXT]).
        - password (str): password dell'utente.
        - associated_data (bytes): dati aggiuntivi autenticati durante la criptazione.
    
    Ritorna:
        - bytes: il plaintext decriptato.
    
    Solleva:
        - ValueError: se il formato dei dati criptati non è corretto.
        - InvalidTag: se i dati sono stati manomessi o la password/AAD è errata.
    '''
    # Estrai salt, nonce, tag e ciphertext dai dati
    if len(encrypted_data) < SALT_BYTES_LENGTH + NONCE_BYTES_LENGTH_GCM + TAG_BYTES_LENGTH_GCM:
        raise ValueError("Dati criptati troppo corti o corrotti.")

    salt = encrypted_data[:SALT_BYTES_LENGTH]
    nonce = encrypted_data[SALT_BYTES_LENGTH : SALT_BYTES_LENGTH + NONCE_BYTES_LENGTH_GCM]
    tag = encrypted_data[SALT_BYTES_LENGTH + NONCE_BYTES_LENGTH_GCM : SALT_BYTES_LENGTH + NONCE_BYTES_LENGTH_GCM + TAG_BYTES_LENGTH_GCM]
    ciphertext = encrypted_data[SALT_BYTES_LENGTH + NONCE_BYTES_LENGTH_GCM + TAG_BYTES_LENGTH_GCM :]

    key = derive_key_from_password_gcm(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    if associated_data is not None:
        decryptor.authenticate_additional_data(associated_data)
    
    # Decripta e verifica il tag
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

#*
#* AUTHENTICATED ENCRYPTION FUNCTIONS (Encrypt-then-MAC EtM)
#*

def encrypt_data_EtM(
    plaintext_data: bytes,
    password: str,
    associated_data: bytes | None = None,
) -> bytes:
    '''
    Cripta dati utilizzando AES-CBC e autentica con HMAC-SHA256 (EtM).
    Il salt, IV e HMAC Tag vengono generati casualmente e inclusi nel ciphertext.

    Parametri:
        - plaintext_data (bytes): dati da criptare.
        - password (str): password dell'utente da cui verranno derivate le chiavi.
        - associated_data (bytes): default None - dati aggiuntivi associati
          al file che non vengono criptati ma solamente autenticati.
    
    Ritorna:
        - bytes: i dati criptati risultanti, concatenati come [SALT] [IV] [HMAC_TAG] [CIPHERTEXT].
    '''
    salt = os.urandom(SALT_BYTES_LENGTH)
    encryption_key, mac_key = derive_keys_from_password_etm(password, salt)
    iv = os.urandom(IV_BYTES_LENGTH_CBC)
    
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded_plaintext = padder.update(plaintext_data) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(encryption_key), 
        modes.CBC(iv), 
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    if associated_data is not None:
        h.update(associated_data)
    h.update(ciphertext)
    hmac_tag = h.finalize()

    encrypted_data = salt + iv + hmac_tag + ciphertext
    return encrypted_data

def decrypt_data_EtM(
    encrypted_data: bytes,
    password: str,
    associated_data: bytes | None = None,
) -> bytes:
    '''
    Decripta dati criptati con AES-CBC e verifica l'autenticità con HMAC-SHA256 (EtM).
    Il salt, IV e HMAC Tag vengono letti dall'inizio dei dati criptati.

    Parametri:
        - encrypted_data (bytes): dati criptati (in formato [SALT] [IV] [HMAC_TAG] [CIPHERTEXT]).
        - password (str): password dell'utente per derivare le chiavi.
        - associated_data (bytes): default None - dati aggiuntivi associati
          al file (devono corrispondere a quelli usati in criptazione).
    
    Ritorna:
        - bytes: i dati decriptati.
    
    Solleva:
        - ValueError: se il formato dei dati criptati non è corretto.
        - InvalidTag: se i dati sono stati manomessi o la password/AAD è errata.
    '''
    # Estrai salt, IV, HMAC Tag e ciphertext dai dati
    min_length = SALT_BYTES_LENGTH + IV_BYTES_LENGTH_CBC + HMAC_TAG_LENGTH_SHA256
    if len(encrypted_data) < min_length:
        raise ValueError("Dati criptati troppo corti o corrotti.")

    salt = encrypted_data[:SALT_BYTES_LENGTH]
    iv = encrypted_data[SALT_BYTES_LENGTH : SALT_BYTES_LENGTH + IV_BYTES_LENGTH_CBC]
    received_hmac_tag = encrypted_data[SALT_BYTES_LENGTH + IV_BYTES_LENGTH_CBC : min_length]
    ciphertext = encrypted_data[min_length:]

    encryption_key, mac_key = derive_keys_from_password_etm(password, salt)

    # Verifica HMAC PRIMA della decifratura
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(iv)
    if associated_data is not None:
        h.update(associated_data)
    h.update(ciphertext)
    h.verify(received_hmac_tag) # Solleva InvalidTag se non corrisponde

    # Decifratura solo se HMAC è valido
    cipher = Cipher(
        algorithms.AES(encryption_key), 
        modes.CBC(iv), 
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext
