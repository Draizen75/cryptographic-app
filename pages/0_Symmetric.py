import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Function to encrypt plaintext
def encrypt_text(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext)

# Function to decrypt ciphertext
def decrypt_text(ciphertext, key):
    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    return plaintext.decode()

def main():
    st.title("AES Encryption and Decryption")

    # Input plaintext
    plaintext = st.text_input("Enter plaintext:", "")

    # Input key
    key = st.text_input("Enter encryption key (16, 24, or 32 bytes):", "")

    # Choose encryption or decryption mode
    mode = st.radio("Select mode:", ("Encrypt", "Decrypt"))

    if mode == "Encrypt":
        if st.button("Encrypt"):
            if plaintext and key:
                try:
                    ciphertext = encrypt_text(plaintext, key.encode())
                    st.success("Ciphertext: " + ciphertext.decode())
                except Exception as e:
                    st.error(f"Encryption failed: {e}")
            else:
                st.warning("Please enter plaintext and encryption key.")

    elif mode == "Decrypt":
        ciphertext = st.text_input("Enter ciphertext:", "")
        if st.button("Decrypt"):
            if ciphertext and key:
                try:
                    plaintext = decrypt_text(ciphertext, key.encode())
                    st.success("Decrypted plaintext: " + plaintext)
                except Exception as e:
                    st.error(f"Decryption failed: {e}")
            else:
                st.warning("Please enter ciphertext and decryption key.")

if __name__ == "__main__":
    main()
