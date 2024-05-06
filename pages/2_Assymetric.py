import streamlit as st
import rsa
from Crypto.Util import number

st.set_page_config(
        page_title="Asymmetric Encryption",
        page_icon="🏷️",
    )

st.write("# Welcome To Asymmetric Encryption🔒🔒🔒")

encryption_type = st.selectbox("Select Encryption Algorithm", ["RSA", "Diffie-Hellman"])

if encryption_type == "RSA":
    st.write("# Welcome To RSA Encryption")
    publickey, privatekey = rsa.newkeys(1024)
    text = st.text_area("Enter your message: ").encode('utf8')

    if st.button("Encrypt"):
        st.write("## Encrypted text in bytes:")
        ciphertext = rsa.encrypt(text, publickey)
        st.code(ciphertext)
        st.write("## Encrypted text in hex:")
        st.code(ciphertext.hex())

        decrypted = rsa.decrypt(ciphertext, privatekey)
        st.write("## Decrypted text:")
        st.code(decrypted.decode('utf8'))

elif encryption_type == "Diffie-Hellman":
    def generate_keys():
        # Generate large prime number
        p = number.getPrime(1024)
        
        # Generate primitive root modulo p
        g = number.getRandomNBitInteger(1024)
        
        while number.GCD(g, p) != 1:
            g = number.getRandomNBitInteger(1024)
        
        # Generate private key
        private_key = number.getRandomNBitInteger(1024)
        
        # Calculate public key
        public_key = pow(g, private_key, p)
        
        return p, g, public_key, private_key

    def encrypt(text, public_key, p, g):
        # Generate shared secret
        shared_secret = pow(public_key, private_key, p)
        
        # Encrypt the text
        encrypted_text = ""
        for char in text:
            encrypted_text += chr((ord(char) + shared_secret) % 256)
        
        return encrypted_text

    def decrypt(encrypted_text, private_key, public_key, p, g):
        # Generate shared secret
        shared_secret = pow(public_key, private_key, p)
        
        # Decrypt the text
        decrypted_text = ""
        for char in encrypted_text:
            decrypted_text += chr((ord(char) - shared_secret) % 256)
        
        return decrypted_text

    st.title("Diffie-Hellman Encryption and Decryption")

   

    if st.sidebar.button("Generate Keys"):
        p, g, public_key, private_key = generate_keys()
        st.sidebar.write("Public Key (p, g, public_key):", p, g, public_key)
        st.sidebar.write("Private Key:", private_key)

    me_option = st.radio(
        "Choose an option:",
        ("Encrypt", "Decrypt")
    )
    if me_option == "Encrypt":
        text = st.text_input("Enter text to encrypt:")
        public_key = st.number_input("Enter recipient's public key:")
        if st.button("Encrypt"):
            encrypted_text = encrypt(text, public_key, p, g)
            st.write("Encrypted Text:", encrypted_text)
            
    elif me_option == "Decrypt":
        encrypted_text = st.text_input("Enter text to decrypt:")
        if st.button("Decrypt"):
            decrypted_text = decrypt(encrypted_text, private_key, public_key, p, g)
            st.write("Decrypted Text:", decrypted_text)

