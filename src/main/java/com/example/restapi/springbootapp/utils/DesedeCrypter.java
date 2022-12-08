package com.example.restapi.springbootapp.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * Encrypt/Decrypt text2text by using Triple-DES
 * 
 * @author Jccm.17
 */
public class DesedeCrypter {
    Logger logger = LogManager.getLogger(DesedeCrypter.class);
    private static final String CRYPT_ALGORITHM = "DESede";
    private static final String PADDING = "DESede/CBC/PKCS5Padding";
    private static final String CHAR_ENCODING = "UTF-8";

    private static final byte[] MY_KEY = "5oquil2oo2vb63e8ionujny6".getBytes();// 24-byte
    private static final byte[] MY_IV = "3oco1v52".getBytes();// 8-byte

    /**
     * Encrypt text to encrypted-text
     * 
     * @param text
     * @return
     */
    public String encrypt(String text) {

        if (text == null) {
            return null;
        }

        String retVal = null;

        try {

            final SecretKeySpec secretKeySpec = new SecretKeySpec(MY_KEY, CRYPT_ALGORITHM);

            final IvParameterSpec iv = new IvParameterSpec(MY_IV);

            final Cipher cipher = Cipher.getInstance(PADDING);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);

            final byte[] encrypted = cipher.doFinal(text.getBytes(CHAR_ENCODING));

            retVal = new String(encodeHex(encrypted));
            logger.info("3-DES encrypt: " + retVal);
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Catch: " + e.getMessage());
        }

        return retVal;
    }

    /**
     * Encrypt file to encrypted-file
     * 
     * @param fileinput
     * @param fileoutput
     * @return
     * @throws FileNotFoundException
     */
    public String encryptFile(File in, File out) throws FileNotFoundException {

        FileInputStream fis = new FileInputStream(in);
        FileOutputStream fos = new FileOutputStream(out);
        
        String retVal = null;

        try {

            final SecretKeySpec secretKeySpec = new SecretKeySpec(MY_KEY, CRYPT_ALGORITHM);

            final IvParameterSpec iv = new IvParameterSpec(MY_IV);

            final Cipher cipher = Cipher.getInstance(PADDING);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, iv);
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            logger.info("3-DES encrypt File: " + cis);
            write(cis, fos);
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Catch: " + e.getMessage());
        }

        return retVal;
    }

    /**
     * Decrypt encrypted-text
     * 
     * @param text
     * @return
     */
    public String decrypt(String text) {

        if (text == null) {
            return null;
        }

        String retVal = null;

        try {

            final SecretKeySpec secretKeySpec = new SecretKeySpec(MY_KEY, CRYPT_ALGORITHM);
            final IvParameterSpec iv = new IvParameterSpec(MY_IV);

            final Cipher cipher = Cipher.getInstance(PADDING);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);

            final byte[] decrypted = cipher.doFinal(decodeHex(text.toCharArray()));

            retVal = new String(decrypted, CHAR_ENCODING);
            logger.info("3-DES decrypt: " + retVal);
        } catch (Exception e) {

            e.printStackTrace();
        }

        return retVal;
    }

    /**
     * decrypt file to encrypted-file
     * 
     * @param fileinput
     * @param fileoutput
     * @return
     * @throws FileNotFoundException
     */
    public String decryptFile(File in, File out) throws FileNotFoundException {

        FileInputStream fis = new FileInputStream(in);
        FileOutputStream fos = new FileOutputStream(out);

        String retVal = null;

        try {

            final SecretKeySpec secretKeySpec = new SecretKeySpec(MY_KEY, CRYPT_ALGORITHM);

            final IvParameterSpec iv = new IvParameterSpec(MY_IV);

            final Cipher cipher = Cipher.getInstance(PADDING);

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, iv);
            CipherOutputStream cos = new CipherOutputStream(fos, cipher);
            logger.info("3-DES decrypt File: " + cos);
            write(fis, cos);
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("Catch: " + e.getMessage());
        }
        return retVal;
    }

    /**
     * 
     * Converts an array of characters representing hexadecimal values into an array
     * of bytes of those same values. The returned array will be half the length of
     * the passed array, as it takes two characters to represent any given byte. An
     * exception is thrown if the passed char array has an odd number of elements.
     * <br>
     * Portion of Apache Software Foundation
     * 
     * @param data
     *             An array of characters containing hexadecimal digits
     * @return A byte array containing binary data decoded from the supplied char
     *         array.
     * @throws Exception
     *                   Thrown if an odd number or illegal of characters is
     *                   supplied
     * 
     * 
     */
    private byte[] decodeHex(char[] data) throws Exception {

        int len = data.length;

        if ((len & 0x01) != 0) {
            throw new Exception("Odd number of characters.");
        }

        byte[] out = new byte[len >> 1];

        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {

            int f = toDigit(data[j], j) << 4;
            j++;
            f = f | toDigit(data[j], j);
            j++;
            out[i] = (byte) (f & 0xFF);
        }

        return out;
    }

    /**
     * Converts a hexadecimal character to an integer. <br>
     * Portion of Apache Software Foundation
     * 
     * @param ch
     *              A character to convert to an integer digit
     * @param index
     *              The index of the character in the source
     * @return An integer
     * @throws Exception
     *                   Thrown if ch is an illegal hex character
     */
    private int toDigit(char ch, int index) throws Exception {
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new Exception("Illegal hexadecimal character " + ch + " at index " + index);
        }
        return digit;
    }

    /**
     * Converts an array of bytes into an array of characters representing the
     * hexadecimal values of each byte in order. The returned array will be double
     * the length of the passed array, as it takes two characters to represent any
     * given byte. <br>
     * Portion of Apache Software Foundation
     * 
     * @param data
     *                 a byte[] to convert to Hex characters
     * @param toDigits
     *                 the output alphabet
     * @return A char[] containing hexadecimal characters
     * 
     * 
     */
    private char[] encodeHex(byte[] data) {

        final char[] DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        int l = data.length;
        char[] out = new char[l << 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; i < l; i++) {
            out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
            out[j++] = DIGITS[0x0F & data[i]];
        }
        return out;
    }

    private static void write(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[64];
        int numOfBytesRead;
        while ((numOfBytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, numOfBytesRead);
        }
        out.close();
        in.close();
    }
}