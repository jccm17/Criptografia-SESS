package com.example.restapi.springbootapp.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RSAEncryption {
    Logger logger = LogManager.getLogger(RSAEncryption.class);
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

    public void encriptarArchivo(File fromFile, File toFile) throws IOException {
        // read a file
        //byte[] fileContent = Files.readAllBytes(fromFile.toPath());
        FileInputStream fis = new FileInputStream(fromFile);
        FileOutputStream fos = new FileOutputStream(toFile);
        //logger.info("File bytes: " + fileContent);
        try {
            Cipher encryptionCipher = Cipher.getInstance("RSA");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            //byte[] encryptedFile = encryptionCipher.doFinal(fileContent);
            CipherInputStream cis = new CipherInputStream(fis, encryptionCipher);
            logger.info("RSA encrypt File: " + cis);
            // save a file
            //Path path = Paths.get(toFile);
            //Files.write(path, encryptedFile);
            write(cis, fos);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("error message = " + e.getMessage());

        }
    }

    public void desencriptarArchivo(File fromEncryptedFile, String toFile) throws IOException {
        // read a file
        byte[] fileContent = Files.readAllBytes(fromEncryptedFile.toPath());
        try {
            Cipher decryptionCipher = Cipher.getInstance("RSA");
            decryptionCipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decryptedFile = decryptionCipher.doFinal(fileContent);
            Path path = Paths.get(toFile);
            Files.write(path, decryptedFile);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("error message = " + e.getMessage());

        }
    }

    private static void write(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[128];
        int numOfBytesRead;
        while ((numOfBytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, numOfBytesRead);
        }
        out.close();
        in.close();
    }
}
