package com.example.restapi.springbootapp.utils;

import java.io.ByteArrayOutputStream;
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

import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RSAEncryption {
    Logger logger = LogManager.getLogger(RSAEncryption.class);
    KeyPairGenerator keyPairGenerator;
    PublicKey publicKey = null;
    PrivateKey privateKey = null;
    public static final int MAX_ENCRYPT_BLOCK = 245;
    public static final int MAX_DECRYPT_BLOCK = 256;

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
        byte[] fileContent = Files.readAllBytes(fromFile.toPath());
        try {
            Cipher encryptionCipher = Cipher.getInstance("RSA");
            encryptionCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            int inputLen = fileContent.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            while (inputLen - offSet > 0) {
                if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = encryptionCipher.doFinal(fileContent, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = encryptionCipher.doFinal(fileContent, offSet, inputLen - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();
            // save a file
            FileOutputStream fos = new FileOutputStream(toFile);
            fos.write(decryptedData);
            fos.close();
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
            // byte[] decryptedFile = decryptionCipher.doFinal(fileContent);
            byte[] enBytes = null;
            for (int i = 0; i < fileContent.length; i += 256) {
                byte[] doFinal = decryptionCipher.doFinal(ArrayUtils.subarray(fileContent, i, i + 256));
                enBytes = ArrayUtils.addAll(enBytes, doFinal);
            }
            // save a file
            FileOutputStream fos = new FileOutputStream(toFile);
            fos.write(enBytes);
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("error message = " + e.getMessage());

        }
    }

}
