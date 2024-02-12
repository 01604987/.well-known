from jwcrypto import jwk
import json

did_id = "did:web:01604987.github.io"
uri = "https://01604987.github.io"

# Load the private key from a PEM file
with open("certs/myKey.pem", "rb") as pemfile:
    pem_data = pemfile.read()

# Create a JWK object from the PEM data
key = jwk.JWK.from_pem(pem_data)

# Export the JWK as a dictionary
public_jwk = key.export_public(as_dict=True)

# not enforced, x5u parameter should resolve to valid x509 .cert .pem .der or .p7b
public_jwk.update({"x5u": f"{uri}/.well-known/myCert.pem"})
# not enforced, algorithm for signing or encryption need to be explicitly added
public_jwk.update({"algo": "RS256"})



context = [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
    ]

assertion_method = [f"{did_id}#myMethod"]
verification_method = [{
    "id" : assertion_method[0],
    "controller": did_id,
    "type": "JsonWebKey2020",
    "publicKeyJwk": public_jwk
}]

did_document = {
    "@context": context,
    "id": did_id,
    "verificationMethod": verification_method,
    "assertionMethod": assertion_method
}

with open("did_test.json", "w") as json_file:
    json.dump(did_document, json_file, indent = 4)
