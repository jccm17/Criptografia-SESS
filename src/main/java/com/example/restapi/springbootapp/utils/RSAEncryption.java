package com.example.restapi.springbootapp.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAEncryption {
    KeyPairGenerator keyPairGenerator;
    PublicKey publicKey = null;
    PrivateKey privateKey = null;

    public RSAEncryption() {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            SecureRandom secureRandom = new SecureRandom();
            keyPairGenerator.initialize(2048, secureRandom);

            KeyPair pair = keyPairGenerator.generateKeyPair();
            publicKey = pair.getPublic();
            String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            System.out.println("RSA public key = " + publicKeyString);
            privateKey = pair.getPrivate();
            String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());
            System.out.println("RSA private key = " + privateKeyString);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String encriptar(String texto) {
        String result;
        try {
            Cipher encryptionCipher = Cipher.getInstance("RSA");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedMessage = encryptionCipher.doFinal(texto.getBytes("UTF-8"));
            result = Base64.getEncoder().encodeToString(encryptedMessage);
            System.out.println("encrypted message = " + result);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("error message = " + e.getMessage());

        }
        return null;
    }

    public String desencriptar(String texto) {
        String result;
        try {
            Cipher decryptionCipher = Cipher.getInstance("RSA");
            decryptionCipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] textDecode = Base64.getDecoder().decode(texto);
            byte[] decryptedMessage = decryptionCipher.doFinal(textDecode);
            result = new String(decryptedMessage);
            System.out.println("decrypted message = " + result);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("error message = " + e.getMessage());

        }
        return null;
    }
}
