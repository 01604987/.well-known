from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import json
import base64


def base64_url_encode(data):
    # Convert input data to bytes if it's not already in bytes format
    data = str(data)
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    encode = base64.urlsafe_b64encode(data).decode()
    return encode.rstrip('=')

# Load the private key
with open("certs/myKey.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = None,
        backend=default_backend()
    )

# Extract the necessary parameters from the private key
private_numbers = private_key.private_numbers()

# Construct the private JWK
private_jwk = {
    "kty": "RSA",
    "n": base64_url_encode(private_numbers.public_numbers.n),
    "e": base64_url_encode(private_numbers.public_numbers.e),
    "d": base64_url_encode(private_numbers.d),
    "p": base64_url_encode(private_numbers.p),
    "q": base64_url_encode(private_numbers.q),
    "dp": base64_url_encode(private_numbers.dmp1),
    "dq": base64_url_encode(private_numbers.dmq1),
    "qi": base64_url_encode(private_numbers.iqmp)
}

# Construct the public JWK
public_jkw = {
    "kty" : private_jwk["kty"],
    "n" : private_jwk["n"],
    "e" : private_jwk["e"],
    "algo" : "RS256",
    "x5u": "http://01604987.github.io/.well-known/myCert.pem"
}



#print(public_jkw)

did_id = "did:web:01604987.github.io"
context = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
    ]

assertion_method = [f"{did_id}#myMethod"]
verification_method = [{
    "id" : assertion_method[0],
    "controller": did_id,
    "type": "JsonWebKey2020",
    "publicKeyJwk": public_jkw
}]


did_document = {
    "@context": context,
    "id": did_id,
    "verificationMethod": verification_method,
    "assertionMethod": assertion_method
}

print(did_document)
with open("did.json", "w") as json_file:
    json.dump(did_document, json_file, indent = 4)
