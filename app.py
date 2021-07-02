import os
from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet
import rsa
from zipfile import ZipFile

app = Flask(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

@app.route("/")
def index():
    #Rendering the homepage
    return render_template("upload.html")

@app.route("/upload", methods=['POST'])
def upload():
    #Getting the filename of the uploaded file
    file = request.files['file']
    filename = (file.filename)
    foldername = os.path.splitext(filename)[0]
    print(filename)
    #creating a new directory dedicated to the uploaded file
    target = os.path.join(APP_ROOT, foldername + '/')
    print(target)

    #If the directory doesn't exist already then create one
    if not os.path.isdir(target):
        os.mkdir(target)

    #Create a symmetric key and store it in a file
    skey = Fernet.generate_key()
    with open(target + "symmetric.key", 'wb') as skey_file:
            skey_file.write(skey)

    #print (request.form['keys'])
    #Creating public and private keys and storing them in their respect files
    (pubkey, privkey) = rsa.newkeys(2048)
    with open(target + "public_key.key", 'wb') as pubkey_file:
        pubkey_file.write(pubkey.save_pkcs1('PEM'))
    with open(target + "private_key.key", 'wb') as privkey_file:
        privkey_file.write(privkey.save_pkcs1('PEM'))


    destination = "/".join([target, filename])
    #print(destination)
    file.save(destination)


    return render_template("complete.html", target = target, filename = filename)

@app.route("/encrypt", methods=['GET' , 'POST'])
def encrypt():

    #Getting the target and filename from the form
    target= str(request.form['target']).strip()
    filename= str(request.form['filename']).strip()

    #Paths for symmetric and public keys and the file to be encrypted
    symmetrickey = (target+"symmetric.key").strip()
    publickey = (target+ "public_key.key").strip()
    file = (target + filename).strip()

    #print ("Symmetric Key exists:"+str(os.path.exists(symmetrickey)))
    #print ("Public Key exists:"+str(os.path.exists(publickey)))
    #print ("File exists:"+str(os.path.exists(file)))

    #Storing the symmetric key in a variable skey
    try:
        with open(symmetrickey, 'rb') as skey_file:
            skey = skey_file.read()
    except FileNotFoundError:
        print("File not found")
    #Storing the public key in a variable pubkey_data
    pubkey_file = open(publickey, 'rb')
    pubkey_data = pubkey_file.read()
    #Loading the public key data
    pubkey = rsa.PublicKey.load_pkcs1(pubkey_data)

    with open(file, 'rb') as f:
        file_b = f.read()

    #Creating a cypher with the symmetric key
    cipher = Fernet(skey)

    #Encrypting the file with the cipher from symmetric key
    encrypt = cipher.encrypt(file_b)

    encryptedfile = filename + " _encrypted"

    with open(target + encryptedfile, 'wb') as e_file:
        e_file.write(encrypt)

    #Encrypting the Symmetric Key file with the public key
    encrypt_key = rsa.encrypt(skey, pubkey)

    with open(target + 'encrypted_key', 'wb') as ek_file:
        ek_file.write(encrypt_key)






    #print (symmetrickey)
    #print ("Yes this file is ready to encrypt " + target)
    #print ("Yes this file is ready to encrypt " + filename)
    return render_template("encrypt.html", target = target, filename = encryptedfile)

@app.route("/download", methods=['GET' , 'POST'])
def download_file():
    target= str(request.form['target']).strip()
    filename= str(request.form['filename']).strip()
    file = target+filename.strip()
    symmetrickey = (target+"encrypted_key").strip()
    publickey = (target+"public_key.key").strip()
    privatekey = (target+"private_key.key").strip()


    zip='EncryptedFiles.zip'
    with ZipFile(zip, 'w') as zipObj:
        zipObj.write(file)
        zipObj.write(symmetrickey)
        zipObj.write(publickey)
        zipObj.write(privatekey)

    zipObj.close()


    return send_file (zip, as_attachment=True, cache_timeout=0)

if __name__ == "__main__":
    app.run(port=4555, debug=True)
