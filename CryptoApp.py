# Copyright (c) Streamlit Inc. (2018-2022) Snowflake Inc. (2022)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import streamlit as st
from streamlit.logger import get_logger

LOGGER = get_logger(__name__)


def run():
    st.set_page_config(
        page_title="Final Project G13",
        page_icon="🌏",
    )

    st.write("# Final Project Applied Cryptography CSAC 329 Cryptographic Application! 👋")

    st.write("""The Applied Cryptography Application project aims to develop a simple application that 
implements various cryptographic techniques to secure communication, data, and information exchange. 
Cryptography is the science of encoding and decoding messages to protect their confidentiality, integrity, 
and authenticity. The application will provide a user-friendly interface that allows users to encrypt, 
decrypt and hash messages/file using different cryptographic algorithms.""")

    st.write("Created by: Group 13")
    st.write("""Members:
                Lloyd Draizen L. Martirez
                Rodney S.R. Celetaria
                Mary Grace B. Hertez""")
    st.write("BSCS 3B")


if __name__ == "__main__":
    run()
