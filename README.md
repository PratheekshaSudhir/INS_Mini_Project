# Secure Data Handling System

## Overview
The **Secure Data Handling System** ensures secure data storage and transmission by using:
- **AES Encryption (Symmetric Key)** to protect data confidentiality.
- **DSA Digital Signatures (Asymmetric Key)** to verify data integrity and authenticity.
- **HTTPS (TLS 1.2) Transmission** to secure API communication against MITM attacks.

This project is built using Flask and PyCryptodome, and it follows a client-server model where users send plaintext data, which is encrypted, signed, and securely stored. The data can be retrieved only if the digital signature is verified.

---

## 📌 Features
✔ **AES Encryption** - Encrypts user data before storage.  
✔ **DSA Digital Signature** - Ensures integrity and authenticity of data.  
✔ **HTTPS Transmission (TLS 1.2)** - Prevents unauthorized access and tampering.  
✔ **Flask API Endpoints** - Provides a REST API for secure data handling.  
✔ **Postman Support** - Fetch outputs using **Postman or any API testing tool**.  

---

## 🚀 Prerequisites
Make sure you have **Python 3.8+** installed. You can check your Python version by running:

```sh
python --version
```

## 🔧 Installation and Setup
**Step 1:** Clone the Repository

```sh
git clone <your-repo-url>
cd <your-project-folder>
```
**Step 2:** Create and Activate a Virtual Environment
For Windows:

```sh
python -m venv venv
venv\Scripts\activate
```
For macOS/Linux:

```sh
python3 -m venv venv
source venv/bin/activate
```
**Step 3:** Install Required Libraries
Install the dependencies manually:

```sh
pip install flask pycryptodome
```
**Step 4:** Generate SSL Certificates (For HTTPS)
If you don't already have cert.pem and key.pem, generate them using OpenSSL:

```sh
mkdir certs
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
```
Ensure the generated .pem files are inside the certs/ directory.

---

## 🎯 Running the Application
Once the setup is complete, start the Flask application by running:

```sh
python app.py
```
The server will start at https://localhost:5000

---

## 📡 API Endpoints and Usage
1️⃣ **Store Encrypted Data**
- **Endpoint:** /store
- **Method:** POST
- **Request Body:**

```json
{
  "data": "Your plaintext data"
}
```
- **Response:**

```json
{
  "message": "Data stored securely",
  "data": {
    "nonce": "GeneratedNonce",
    "encrypted_data": "EncryptedData",
    "tag": "GeneratedTag",
    "signature": "DigitalSignature"
  }
}
```

2️⃣ **Retrieve and Verify Data**
- **Endpoint:** /retrieve
- **Method:** POST
- **Request Body:** (Use the values received from /store)

```json
{
  "nonce": "GeneratedNonce",
  "encrypted_data": "EncryptedData",
  "tag": "GeneratedTag",
  "signature": "DigitalSignature"
}
```

- **Response:**

✅ **If valid:**
```json
{
  "decrypted_data": "Your original plaintext data",
  "signature_status": "Signature is valid."
}
```

❌ **If tampered:**
```json
{
  "error": "Invalid signature. Data may be compromised."
}
```

--- 

## 🛠 Testing with Postman or Any API Tool
You can test these API endpoints using Postman, Thunder Client (VS Code), or cURL.

### 📌 Steps to Use Postman:
1) Open Postman and create a new request.

2) Set the request type to POST.

3) Enter the endpoint URL (https://localhost:5000/store or https://localhost:5000/retrieve).

4) Navigate to the Body tab and select raw → JSON.

5) Paste the required JSON payload and hit Send.

6) View the response in Postman.

---

## 🔄 Workflow
1) User sends plaintext data via the /store endpoint.

2) AES Encryption: The server encrypts the data using AES.

3) Digital Signature: The server signs the encrypted data using a DSA private key.

4) Secure Storage: The server stores the encrypted data, nonce, tag, and signature.

5) User requests retrieval via the /retrieve endpoint.

6) Signature Verification: The server verifies the digital signature.

7) Decryption: If the signature is valid, the data is decrypted and sent to the user.

8) Rejection: If the signature is tampered, decryption is denied.

## Link to run the code in collab:

https://colab.research.google.com/drive/1dXqCrhJT0IM1cp8f40KoJUKNQkf65Z3I?usp=sharing

Note: please make sure to put path of the key.pem and cert.pem files correctly

