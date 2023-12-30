from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import base64

# Generar un par de claves (privada y pública)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Convertir la clave privada a string
private_key_str = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

# Convertir la clave pública a string
public_key_str = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Convertir string a clave privada
private_key_from_str = serialization.load_pem_private_key(
    private_key_str.encode('utf-8'),
    password=None,
    backend=default_backend()
)

# Convertir string a clave pública
public_key_from_str = serialization.load_pem_public_key(
    public_key_str.encode('utf-8'),
    backend=default_backend()
)

message = b"Este es un mensaje secreto"

# Firma el mensaje con la clave privada
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Convertir la firma a string (base64)
signature_str = base64.b64encode(signature).decode('utf-8')

# Convertir string (base64) a firma
signature_from_str = base64.b64decode(signature_str)