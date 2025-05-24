# Secure File Handling with Authenticated Encryption

## Project Overview

This project implements a secure file handling application focusing on **Authenticated Encryption (AE)**. The primary goal is to provide confidentiality and integrity for sensitive documents by encrypting them before storage and decrypting them on demand. The application will explore different modes of Authenticated Encryption, comparing their performance and security properties.

## Problem Statement

In an era where digital information is paramount, the secure storage and handling of sensitive documents is a critical concern for individuals and organizations alike. Traditional encryption methods, while providing confidentiality, often lack inherent mechanisms to guarantee data integrity and authenticity. This project addresses this gap by leveraging Authenticated Encryption, ensuring that encrypted files are not only unreadable to unauthorized parties but also demonstrably untampered with.

## Theoretical Background

Authenticated Encryption (AE) is a form of encryption that simultaneously provides confidentiality, integrity, and authenticity. It aims to protect data from unauthorized disclosure and detect any unauthorized modifications. This project will primarily focus on symmetric key AE algorithms, comparing their operational modes.

Key concepts to be explored and implemented include:

* **Confidentiality:** Ensuring that data remains private.
* **Integrity:** Guaranteeing that data has not been altered or corrupted.
* **Authenticity:** Verifying that the data originates from a legitimate source.
* **Associated Data (AAD):** Additional data that is authenticated but not encrypted (e.g., file metadata).

## Implemented Authenticated Encryption Modes

The application will implement and compare at least two different Authenticated Encryption modes. This section will be updated with the specific modes chosen (e.g., AES-GCM, AES-CCM, or Encrypt-then-MAC with AES-CBC + HMAC) and the rationale behind their selection.

## Design Choices

### Programming Language

* **Python:** Chosen for its rich ecosystem of cryptographic libraries (e.g., `cryptography`), rapid prototyping capabilities, and readability, facilitating clear implementation and documentation.

### Core Functionalities

* **Encryption:** Securely encrypts a given file using a specified AE mode and a user-provided key.
* **Decryption:** Securely decrypts an encrypted file using the correct key, verifying its integrity and authenticity.
* **Performance Comparison:** Benchmarking tools to compare the speed of encryption and decryption across different AE modes.
* **Security Analysis:** Discussion and demonstration of the security properties provided by AE, and potential vulnerabilities if not correctly applied.

### Potential User Interface (Future Enhancement)

While the initial implementation will likely be command-line driven, a web-based Graphical User Interface (GUI) built with React could be developed as an extra functionality, providing a more intuitive user experience for file selection, key input, and operation execution.

## How to Run

*(This section will be populated once the basic structure is in place. It will include instructions for setting up the environment, installing dependencies, and running the encryption/decryption commands.)*

## Security Considerations

This project will explicitly address:

* **Potential Vulnerabilities:** Discussing risks associated with improper use of cryptographic primitives (e.g., Nonce/IV reuse, weak key management).
* **Types of Attacks:** Analyzing how different attacks (e.g., replay attacks, chosen-ciphertext attacks, side-channel attacks) could theoretically affect the system and how AE mitigates them.
* **Security Objectives:** Clearly defining how confidentiality, integrity, and authenticity are achieved.
* **Methodologies:** Outlining the best practices and cryptographic primitives used to ensure the desired security posture.

## Authors

* Francesca Maria Palazzotto
* LM-18 Data, Algorithms and Machine Intelligence

---
