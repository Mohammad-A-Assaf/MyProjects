function showTab(tab){
    document.getElementById('login-form').style.display = (tab === 'login') ? 'block' : 'none';
    document.getElementById('register-form').style.display = (tab === 'registre') ? 'block' : 'none';
}   

document.getElementById('upload-btn').addEventListener('click', async () =>{
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    if(!file){
        alert("Please select a file.");
        return;
    }

    // Retrieve users RSA public Key from the server (we need a new endpoint)
    const publicKeyPem = await fetchPublicKeyFromServer();

    // perform the Gybrid Encryption in crypto.js
    const encryptedData = await encryptAndWrapFile(file, publicKeyPem);

    // Send encrypted package to Flask backend
    await sendEncryptedFile(encryptedData, file.name);
});