# Image Steganography AES + RSA (StegaCrypt)

A Python-based GUI tool using **AES-256 encryption**, **RSA-2048 key wrapping**, and **LSB steganography** to securely hide and extract secret messages within images for private, end-to-end encrypted communication.  
Rebuilt and maintained by **Chandan Agarwal**.

## Features

- **Hybrid Encryption (AES + RSA):**  
  Encrypts messages using **AES-256 GCM**, then secures the AES key using **RSA-2048 OAEP**, ensuring that only the intended private-key holder can decrypt the hidden message.

- **LSB Image Steganography:**  
  Uses Least Significant Bit (LSB) encoding to embed encrypted payloads inside image pixels with minimal visual distortion.

- **User-Friendly GUI:**  
  Tkinter-based interface with image preview, capacity indicators, encryption/decryption controls, and optional RSA keypair generation.

## Tech Stack

- **Python 3.x:**  
  Core programming language for application logic.

- **Tkinter:**  
  Provides a clean graphical interface.

- **Pillow (PIL):**  
  Handles image loading, processing, and pixel manipulation.

- **cryptography:**  
  Implements AES-256 GCM symmetric encryption and RSA-2048 OAEP asymmetric encryption.

- **NumPy:**  
  Used for efficient image/pixel data manipulation.

## Requirements

Install the required dependencies using:
pip install -r requirements.txt

## Contact

GitHub: [@Chandan-1206](https://github.com/Chandan-1206)
LinkedIn: https://www.linkedin.com/in/chandan-agarwal-823b47280/

## This project is Open source.
