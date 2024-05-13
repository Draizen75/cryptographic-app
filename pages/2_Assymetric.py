import streamlit as st
import rsa
from Crypto.Util import number

st.set_page_config(
        page_title="Asymmetric Encryption",
        page_icon="🏷️",
    )

st.write("# Welcome To Asymmetric Encryption")

encryption_type = st.selectbox("Select Encryption Algorithm", ["RSA", "Diffie-Hellman"])

if encryption_type == "RSA":
    st.write("## Welcome To RSA Encryption")
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

    import streamlit as st

    def modexp(b, e, m):
        """Efficient modular exponentiation"""
        result = 1
        b = b % m
        while e > 0:
            if e % 2 == 1:
                result = (result * b) % m
            e = e >> 1
            b = (b * b) % m
        return result

    def generate_shared_secret(p, g, a, b):
        """Generate shared secret using Diffie-Hellman key exchange"""
        A = modexp(g, a, p)
        B = modexp(g, b, p)
        secret_A = modexp(B, a, p)
        secret_B = modexp(A, b, p)
        if secret_A == secret_B:
            return secret_A
        else:
            return None

    def encrypt(text, key):
        """Encrypt plaintext using a key"""
        return ''.join([chr((ord(char) + key) % 256) for char in text])

    def decrypt(text, key):
        """Decrypt ciphertext using a key"""
        return ''.join([chr((ord(char) - key) % 256) for char in text])

    st.write("## Diffie-Hellman Encryption and Decryption")

    p = st.sidebar.number_input("Enter a prime number (p):", min_value=2, step=1)
    g = st.sidebar.number_input("Enter a generator (g):", min_value=2, step=1)

    st.write("Choose private keys for Alice and Bob:")
    a = st.number_input("Alice's private key (a):", min_value=1, step=1)
    b = st.number_input("Bob's private key (b):", min_value=1, step=1)

    shared_secret = generate_shared_secret(p, g, a, b)

    if shared_secret:
        st.write(f"Shared Secret Key: {shared_secret}")

        plaintext = st.text_input("Enter the plaintext:")
        if st.button("Encrypt"):
            encrypted_text = encrypt(plaintext, shared_secret)
            st.write(f"## :green[Encrypted text]: {encrypted_text}")
            
            decrypted_text = decrypt(encrypted_text, shared_secret)
            st.write(f"## :red[Decrypted text]: {decrypted_text}")

    else:
        st.write("Invalid private keys. Please choose different private keys.")
