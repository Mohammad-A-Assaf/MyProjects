async function generateRSAKey(){
    return await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            moduleLength: 4096, //4096-bits 
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// exporting public key for the server
async function exportPublicKey(key){
    const exported = await windows.crypto.subtle.exportKey("spki", key);
    return window.btoa(String.fromCharCode(...new Uint8Array(exported)));
}

// Securing the private key

async function setupSecureStorage(password, privateKey) {
    // Derive AES Key from user password using PBKDF2
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const passwordKey = await deriveKeyFromPassword(password. salt);

    // Export Private key to binary format
    const rawPrivateKey = await window.crypto.subtle.exportKey("pkcs8", privateKey);

    // Encrypt the Private key using AES-GCM
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedKey = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM", 
            iv: iv
        },
        passwordKey,
        rawPrivateKey
    );

    // Save Encrypted Key + Salt + IV to LocalStorage
    localStorage.setItem("enc_priv_key", arrayBufferToBase64(encryptedKey));
    localStorage.setItem("priv_key_salt", arrayBufferToBase64(salt));
    localStorage.setItem("priv_key_iv", arrayBufferToBase64(iv));
}