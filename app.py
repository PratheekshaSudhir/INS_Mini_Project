from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
import os

app = Flask(__name__)

# Generate AES Key for Encryption (Stored securely in production)
AES_KEY = os.urandom(16)

# Generate DSA Keys for Digital Signatures
DSA_KEY = DSA.generate(2048)
PUBLIC_KEY = DSA_KEY.publickey()

# Encrypt data using AES
def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return nonce.hex(), ciphertext.hex(), tag.hex()

# Decrypt data using AES
def decrypt_data(nonce, ciphertext, tag):
    cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=bytes.fromhex(nonce))
    data = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), bytes.fromhex(tag))
    return data.decode()

# Sign data using DSA
def sign_data(data):
    hash_obj = SHA256.new(data.encode())
    signer = DSS.new(DSA_KEY, 'fips-186-3')
    signature = signer.sign(hash_obj)
    return signature.hex()

# Verify digital signature
def verify_signature(data, signature):
    hash_obj = SHA256.new(data.encode())
    verifier = DSS.new(PUBLIC_KEY, 'fips-186-3')
    try:
        verifier.verify(hash_obj, bytes.fromhex(signature))
        return "Signature is valid."
    except ValueError:
        return "Signature is invalid."

@app.route('/store', methods=['POST'])
def store_data():
    try:
        content = request.json.get("data")
        nonce, encrypted_data, tag = encrypt_data(content)
        signature = sign_data(content)
        
        # Store in a secure DB (Simulated)
        stored_data = {
            "nonce": nonce,
            "encrypted_data": encrypted_data,
            "tag": tag,
            "signature": signature
        }
        
        return jsonify({"message": "Data stored securely", "data": stored_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/retrieve', methods=['POST'])
def retrieve_data():
    try:
        received_data = request.json
        nonce = received_data["nonce"]
        encrypted_data = received_data["encrypted_data"]
        tag = received_data["tag"]
        signature = received_data["signature"]

        # Decrypt data
        decrypted_data = decrypt_data(nonce, encrypted_data, tag)

        # Verify digital signature
        signature_status = verify_signature(decrypted_data, signature)
        if signature_status != "Signature is valid.":
            return jsonify({"error": "Invalid signature. Data may be compromised."}), 400

        # Now proceed with decryption only if signature is valid
        decrypted_data = decrypt_data(nonce, encrypted_data, tag)


        return jsonify({
            "decrypted_data": decrypted_data,
            "signature_status": signature_status
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Use HTTPS (TLS 1.2)
    context = ('certs/cert.pem', 'certs/key.pem')  # Updated path
    app.run(ssl_context=context, host='0.0.0.0', port=5000)
