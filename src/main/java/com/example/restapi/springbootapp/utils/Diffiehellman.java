package com.example.restapi.springbootapp.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Jccm.17
 */

public class Diffiehellman {
    Logger logger = LogManager.getLogger(Diffiehellman.class);

    // ~ --- [Declaracion de Campos]
    // ------------------------------------------------------------------------------------------

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey receivedPublicKey;
    private byte[] secretKey;
    private String secretMessage;

    public Diffiehellman() {
        generateCommonSecretKey();
    }

    // ~ --- [METHODS]
    // --------------------------------------------------------------------------------------------------
    public void encryptAndSendMessage(final String message, final Diffiehellman person) {

        try {

            // Tu puedes usar Blowfish u otro algoritmo asimetrico pero tu mejor ajusta el
            // tamaño de llave.
            final SecretKeySpec keySpec = new SecretKeySpec(secretKey, "DES");
            final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            final byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            logger.info("encryptedMessage: " + encryptedMessage);
            person.receiveAndDecryptMessage(encryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void generateCommonSecretKey() {
        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);

            secretKey = shortenSecretKey(keyAgreement.generateSecret());
            logger.info("secretKey: " + secretKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ~
    // ----------------------------------------------------------------------------------------------------------------

    public void generateKeys() {

        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(1024);

            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ~
    // ----------------------------------------------------------------------------------------------------------------

    public PublicKey getPublicKey() {

        return publicKey;
    }

    // ~
    // ----------------------------------------------------------------------------------------------------------------

    public void receiveAndDecryptMessage(final byte[] message) {

        try {

            // You can use Blowfish or another symmetric algorithm but you must adjust the
            // key size.
            final SecretKeySpec keySpec = new SecretKeySpec(secretKey, "DES");
            final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

            cipher.init(Cipher.DECRYPT_MODE, keySpec);

            secretMessage = new String(cipher.doFinal(message));
            logger.info("secretMessage: " + secretMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ~
    // ----------------------------------------------------------------------------------------------------------------

    /**
     * In a real life example you must serialize the public key for transferring.
     *
     * @param person
     */
    public void receivePublicKeyFrom(final Diffiehellman person) {

        receivedPublicKey = person.getPublicKey();
    }

    // ~
    // ----------------------------------------------------------------------------------------------------------------

    public void whisperTheSecretMessage() {

        System.out.println(secretMessage);
    }

    // ~
    // ----------------------------------------------------------------------------------------------------------------

    /**
     * 1024 bit symmetric key size is so big for DES so we must shorten the key
     * size. You can get first 8 longKey of the
     * byte array or can use a key factory
     *
     * @param longKey
     *
     * @return
     */
    private byte[] shortenSecretKey(final byte[] longKey) {

        try {

            // Usa 8 bytes (64 bits) para DES, 6 bytes (48 bits) para Blowfish
            final byte[] shortenedKey = new byte[8];

            System.arraycopy(longKey, 0, shortenedKey, 0, shortenedKey.length);

            return shortenedKey;

            // Below lines can be more secure
            // final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            // final DESKeySpec desSpec = new DESKeySpec(longKey);
            //
            // return keyFactory.generateSecret(desSpec).getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
