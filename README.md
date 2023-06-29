# Chat Server with End-to-End Encryption using PGP Encryption

This is a chat server project written in C# that implements end-to-end encryption using PGP (Pretty Good Privacy) encryption. The program utilizes RSA-2048 encryption to exchange session keys, and messages are encrypted using AES-128 (Advanced Encryption Standard).

## Features

- Secure communication: All messages sent between clients are encrypted using PGP encryption, ensuring confidentiality and integrity of the communication.
- RSA key exchange: RSA encryption is used to securely exchange session keys between clients, establishing a shared secret for AES encryption.
- AES encryption: Messages are encrypted using AES with the session key obtained through RSA key exchange, providing fast and efficient encryption.
- User-friendly interface: The chat server provides a simple and intuitive interface for users to send and receive encrypted messages.

## Contributing

Contributions to this project are welcome. If you would like to contribute, please follow these steps:

1. Fork the repository.

2. Create a new branch for your feature or bug fix.

3. Make your changes and ensure that the code compiles successfully.

4. Write tests for your changes, if applicable.

5. Commit your changes and push them to your fork.

6. Submit a pull request, explaining your changes and their purpose.

## License

This project is licensed under the [MIT License](LICENSE).

We appreciate your interest in our project and look forward to your feedback!

