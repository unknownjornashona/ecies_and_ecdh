#include "EncryptionManager.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <plaintext_file> <ciphertext_file> <decrypted_file>" << std::endl;
        return 1;
    }

    std::string plaintextFile = argv[1];
    std::string ciphertextFile = argv[2];
    std::string decryptedFile = argv[3];

    try {
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        EncryptionManager encryptionManager;

        // Generate key pair
        UniqueECKey myKeyPair = encryptionManager.generate_key_pair();
        encryptionManager.save_private_key("my_private_key.pem", myKeyPair);
        encryptionManager.save_public_key("my_public_key.pem", myKeyPair);

        // Load peer public key (for testing, we'll use our own public key)
        UniqueECKey peerKey = encryptionManager.load_public_key("my_public_key.pem");

        // Derive shared secret
        std::vector<uint8_t> sharedSecret;
        encryptionManager.derive_shared_secret(myKeyPair.get(), peerKey.get(), sharedSecret);

        // Load plaintext from specified file and encrypt
        std::vector<uint8_t> plaintext = encryptionManager.load_from_file(plaintextFile);
        std::vector<uint8_t> ciphertext;
        encryptionManager.encrypt_data(plaintext, sharedSecret, ciphertext);

        // Save ciphertext to specified file
        encryptionManager.save_to_file(ciphertextFile, ciphertext);

        std::cout << "Encryption successful! Ciphertext saved to " << ciphertextFile << std::endl;

        // Decrypting the ciphertext to verify
        std::vector<uint8_t> decryptedText;
        encryptionManager.decrypt_data(ciphertext, sharedSecret, decryptedText);
        
        // Save decrypted text to specified file
        encryptionManager.save_to_file(decryptedFile, decryptedText);
        
        std::cout << "Decryption successful! Decrypted text saved to " << decryptedFile << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }
    return 0;
}
