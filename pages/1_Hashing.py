import streamlit as st

# Function to encrypt text using Caesar cipher
def encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

# Function to decrypt text using Caesar cipher
def decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
            decrypted_text += chr(shifted)
        else:
            decrypted_text += char
    return decrypted_text

def main():
    st.title("Caesar Cipher Encryption and Decryption")
    st.sidebar.title("Options")

    plaintext = st.text_input("Enter text to encrypt/decrypt:")
    file_upload = st.file_uploader("Upload a text file")

    shift = st.sidebar.slider("Select shift value:", 1, 25, 3)

    if plaintext:
        st.subheader("Encrypted Text:")
        encrypted_text = encrypt(plaintext, shift)
        st.write(encrypted_text)

        st.subheader("Decrypted Text:")
        decrypted_text = decrypt(encrypted_text, shift)
        st.write(decrypted_text)

    if file_upload is not None:
        file_contents = file_upload.getvalue().decode("utf-8")
        st.subheader("File Contents:")
        st.write(file_contents)

        st.subheader("Encrypted File Contents:")
        encrypted_file_contents = encrypt(file_contents, shift)
        st.write(encrypted_file_contents)

        st.subheader("Decrypted File Contents:")
        decrypted_file_contents = decrypt(encrypted_file_contents, shift)
        st.write(decrypted_file_contents)

if __name__ == "__main__":
    main()
