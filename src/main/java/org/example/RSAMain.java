package org.example;

import RSA.RSADecrypt;
import RSA.RSAEncrypt;
import RSAKey.KeyToFiles;
import RSAKey.RSAKeyGenerator;
import RSAKey.ExtractKeysFromFile;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class RSAMain {
    public static void main(String[] args) throws Exception {
        System.out.println("Secret message to be encrypted : "+ args[0]);
        String message = args[0];
        KeyPair pair = getKeyPair(); // Step 1: Generate RSA key pair
        saveKeysToFiles(pair); // Step 2: Save the keys to files
        ExtractKeys key = getExtractKeys(); //Step 3: extract keys from file
        EncryptedMessage RSAEncryptionResult = getEncryptedMessage(key, message); // Step 4: Encrypt a sentence using the private key in the file
        System.out.println("\n Encrypted Message: \n" + RSAEncryptionResult.encodedMessage());
        String decryptedMessage = getDecryptedMessage(key, RSAEncryptionResult); // Step 5: Decrypt the encrypted text using the public key in the file
        System.out.println("\n Decrypted Message: \n" + decryptedMessage);
    }

    private static String getDecryptedMessage(ExtractKeys key, EncryptedMessage rsaEncryptionResult) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("\n Public Key used by recipient for decrypting message: \n" + key.publicKey());
        RSADecrypt rsa = new RSADecrypt(key.publicKey(), rsaEncryptionResult.encryptedMessage());
        return rsa.RSAEncryptDecrypt();
    }

    private static EncryptedMessage getEncryptedMessage(ExtractKeys key, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        System.out.println("\n Private key used by sender for encrypting message: \n" + key.privateKey());
        RSAEncrypt rsaEncrypt = new RSAEncrypt(key.privateKey(), message);
        byte[] encryptedMessage = rsaEncrypt.getRsaEncryptedMessage();
        String encodedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
        return new EncryptedMessage(encryptedMessage, encodedMessage);
    }

    private record EncryptedMessage(byte[] encryptedMessage, String encodedMessage) {
    }

    private static ExtractKeys getExtractKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = (PublicKey) ExtractKeysFromFile.getKey("publicKey.pem", "public");
        PrivateKey privateKey = (PrivateKey) ExtractKeysFromFile.getKey("privateKey.pem", "private");
        return new ExtractKeys(publicKey, privateKey);
    }

    private record ExtractKeys(PublicKey publicKey, PrivateKey privateKey) {
    }

    private static void saveKeysToFiles(KeyPair pair) throws IOException {
        KeyToFiles keyfile = new KeyToFiles();
        keyfile.savePemFile("publicKey.pem", "PUBLIC KEY", pair.getPublic().getEncoded());
        keyfile.savePemFile("privateKey.pem", "PRIVATE KEY", pair.getPrivate().getEncoded());
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        RSAKeyGenerator rsakey = new RSAKeyGenerator();
        return rsakey.getKeyGenerator();
    }

}
