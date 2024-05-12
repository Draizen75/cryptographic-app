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

    import streamlit as st
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import scrypt
    from Crypto.Protocol import KDF
    import hashlib

    def generate_public_key(g, p, private_key):
        return (g ** private_key) % p

    def generate_shared_secret(public_key, private_key, p):
        return (public_key ** private_key) % p

    def encrypt_message(message, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        return ct_bytes, cipher.iv

    def decrypt_message(ct_bytes, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        return pt.decode()

st.title("Secure Messaging App")

    p = st.number_input("Enter a prime number (p):", min_value=1, step=1)
    g = st.number_input("Enter a primitive root of p (g):", min_value=1, step=1)

    private_key_A = st.number_input("Enter private key for User A:", min_value=1, step=1)
    private_key_B = st.number_input("Enter private key for User B:", min_value=1, step=1)

    message = st.text_area("Enter your message:")

    if st.button("Generate Public Keys"):
        public_key_A = generate_public_key(g, p, private_key_A)
        public_key_B = generate_public_key(g, p, private_key_B)

        st.write("Public Key for User A:", public_key_A)
        st.write("Public Key for User B:", public_key_B)

    if st.button("Generate Shared Secret"):
        shared_secret_A = generate_shared_secret(public_key_B, private_key_A, p)
        shared_secret_B = generate_shared_secret(public_key_A, private_key_B, p)

        if shared_secret_A == shared_secret_B:
            st.success("Shared secret generated successfully!")
            st.write("Shared Secret:", shared_secret_A)
        else:
            st.error("Error generating shared secret!")

    if st.button("Encrypt Message"):
        key = scrypt(shared_secret_A.encode(), "salt", 16, N=2**14, r=8, p=1)
        ct_bytes, iv = encrypt_message(message, key)
        st.write("Encrypted Message:", ct_bytes)
        st.write("Initialization Vector (IV):", iv)

    if st.button("Decrypt Message"):
        key = scrypt(shared_secret_B.encode(), "salt", 16, N=2**14, r=8, p=1)
        decrypted_message = decrypt_message(ct_bytes, key, iv)
        st.write("Decrypted Message:", decrypted_message)
