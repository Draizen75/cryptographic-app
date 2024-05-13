import streamlit as st
import os

st.set_page_config(
        page_title="Symmetric Encryption",
        page_icon="🔑",
    )

st.write("# : red Welcome To Symmetric Encryption")

encryption_type = st.selectbox("Select Encryption Algorithm", ["XOR Cipher", "Caesar Cipher"])

if encryption_type == "XOR Cipher":
    def xor_encrypt(plaintext, key):
        """Encrypts plaintext using XOR cipher with the given key."""
        ciphertext = bytearray()
        for i in range(len(plaintext)):
            plaintext_byte = plaintext[i]
            key_byte = key[i % len(key)]
            cipher_byte = plaintext_byte ^ key_byte
            ciphertext.append(cipher_byte)
        return ciphertext

    def xor_decrypt(ciphertext, key):
        """Decrypts ciphertext using XOR cipher with the given key."""
        return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption

    # Example usage:
    st.write("# Welcome To XOR Cipher")
    option = st.radio("Choose an option:", ("Text", "File"))

    if option == "Text":
        plaintext = bytes(st.text_area("Text:").encode())
        key = bytes(st.text_area("Key:").encode())
        if st.button("Encrypt"):
            col1, col2 = st.columns(2)
            if plaintext == key:
                st.write("Plaintext should not be equal to the key")
            elif len(plaintext.decode()) < len(key.decode()):
                st.write("Plaintext length should be greater than or equal to the key length")
            else:
                with col1:
                    encrypted_text = xor_encrypt(plaintext, key)
                    st.write("Encrypted Text:", encrypted_text.decode())
                with col2:
                    decrypted_text = xor_decrypt(encrypted_text, key)
                    st.write("Decrypted Text:", decrypted_text.decode())

    elif option == "File":
        uploaded_file = st.file_uploader("Upload a file")
        if uploaded_file is not None:
            filetype = os.path.splitext(uploaded_file.name)[-1][1:]
            if filetype == "enc":  # If uploaded file is encrypted
                key = bytes(st.text_area("Key:").encode())
                if st.button("Decrypt"):
                    file_contents = uploaded_file.read()
                    decrypted_file_contents = xor_decrypt(file_contents, key)
                    st.write("File Decrypted")
                    
                    # Get the original file extension
                    original_filename = uploaded_file.name[:-4]
                    st.download_button(
                        label="Download Decrypted File",
                        data=bytes(decrypted_file_contents),  # Convert to bytes
                        file_name=original_filename,
                        mime="application/octet-stream"
                    )
            else:  # If uploaded file is not encrypted
                key = bytes(st.text_area("Key:").encode())
                if st.button("Encrypt"):
                    file_contents = uploaded_file.read()
                    encrypted_file_contents = xor_encrypt(file_contents, key)
                    st.write("File Encrypted")
            
                    st.download_button(
                        label="Download Encrypted File",
                        data=bytes(encrypted_file_contents),  # Convert to bytes
                        file_name=f"{uploaded_file.name}.enc",
                        mime="application/octet-stream"
                    )

elif encryption_type == "Caesar Cipher":
    def encrypt_decrypt_text(text, shift_keys, ifdecrypt):

        result = ""
        
        for n, char in enumerate(text):
            if isinstance(char, int):
                result += chr(char)
            else:
                shift_key = shift_keys[n % len(shift_keys)] 
                if 32 <= ord(char) <= 126:
                    if ifdecrypt:
                        new_char = chr((ord(char) - shift_key - 32 ) % 94 + 32)
                    else:
                        new_char = chr((ord(char) + shift_key - 32 ) % 94 + 32 )
                    result += new_char
                
                else:
                    result += char
        return result

    def encrypt_decrypt_file(file, shift_keys, ifdecrypt):
        result = ""
        file_contents = file.read()
        result = encrypt_decrypt_text(file_contents, shift_keys, ifdecrypt)
        return result

    st.write("# Welcome To Caesar Cipher🔒🔒🔒")
    option = st.radio("Choose what you want to encrypt:", ("Text", "File"))
    text = ""
    file = ""
    if option == "Text":
        text = st.text_area("Plaintext:")
        shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
        if st.button("Encrypt"):
            encrypt = encrypt_decrypt_text(text, shift_keys, ifdecrypt=False)
            decrypt = encrypt_decrypt_text(encrypt, shift_keys, ifdecrypt=True)
            st.write("Encrypted Text:", encrypt)
            st.write("Decrypted text:", decrypt)


    elif option == "File":
        upfile = st.file_uploader("Upload a file")
        if upfile is not None:
            filetype = os.path.splitext(upfile.name)[-1][1:]
            if filetype == "enc":  # If uploaded file is encrypted
                shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
                if st.button("Decrypt"):
                    decrypted_file_contents = encrypt_decrypt_file(upfile, shift_keys, ifdecrypt=True)
                    st.write("File Decrypted")
                    
                    # Get the original file extension
                    original_filename = upfile.name[:-4]
                    st.download_button(
                        label="Download Decrypted File",
                        data=bytes(decrypted_file_contents.encode()),  # No need to convert to bytes
                        file_name=original_filename,
                        mime="application/octet-stream"
                    )
            else:
                shift_keys = list(map(int, st.text_area("Shift Keys:").split()))
                if st.button("Encrypt"):
                    encrypted_file_contents = encrypt_decrypt_file(upfile, shift_keys, ifdecrypt=False)
                    st.write("File Encrypted")
                    
                    # Get the original file extension
                    
                    st.download_button(
                        label="Download Encrypted File",
                        data=bytes(encrypted_file_contents.encode()),
                        file_name=f"{upfile.name}.enc",
                        mime="application/octet-stream"
                    )