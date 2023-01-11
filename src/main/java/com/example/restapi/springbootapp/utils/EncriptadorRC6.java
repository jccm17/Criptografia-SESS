package com.example.restapi.springbootapp.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.util.Base64Utils;
/**
 *
 * @author Jccm.17
 */
public class EncriptadorRC6 {

    static Logger logger = LogManager.getLogger(EncriptadorRC6.class);
    private static int w = 32;
    private static int r = 20;
    private static int Pw = 0xB7E15163;
    private static int Qw = 0x9E3779b9;
    private static int[] S = new int[r * 2 + 4];
    private static byte[] output;
    private static int counter = 0;
    private static int plainTextLength;
    private static final byte[] MY_KEY = "5oquil2oo2vb63e8ionujny6".getBytes();// 24-byte
    private static final String CHAR_ENCODING = "UTF-8";
    public static final int MAX_ENCRYPT_BLOCK = 245;
    public static final int MAX_DECRYPT_BLOCK = 256;

    private static String ALGORITHM_NAME = "RC6";
    private static String MODE_OF_OPERATION = "ECB";
    private static String PADDING_SCHEME = "PKCS5Padding";
    private static SecretKey secretKey;
    private final static int RC6_KEYLENGTH = 128;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    
    private static int rotateLeft(int n, int x) {
        return ((n << x) | (n >>> (w - x)));
    }

    private static int rotateRight(int n, int x) {
        return ((n >>> x) | (n << (w - x)));
    }

    /*
     * Funcion: convertToHex
     */

    private static byte[] convertToHex(int regA, int regB, int regC, int regD) {
        int[] data = new int[4];
        byte[] text = new byte[w / 2];
        data[0] = regA;
        data[1] = regB;
        data[2] = regC;
        data[3] = regD;

        for (int i = 0; i < text.length; i++) {
            text[i] = (byte) ((data[i / 4] >>> (i % 4) * 8) & 0xff);
        }

        return text;
    }

    /*
     * Funcion: mergeArrays
     */
    private static void mergeArrays(byte[] array) {
        for (int i = 0; i < array.length; i++) {
            output[counter] = array[i];
            counter++;
        }
    }

    /*
     * Funcion: fillBufferZeroes
     */
    private static byte[] fillBufferZeroes(byte[] plainText) {
        int length = 16 - plainText.length % 16;
        byte[] block = new byte[plainText.length + length];
        for (int i = 0; i < plainText.length; i++) {
            block[i] = plainText[i];
        }
        for (int i = plainText.length; i < plainText.length + length; i++) {
            block[i] = 0;
        }
        return block;
    }

    /*
     * Funcion: clearPadding
     */
    private static byte[] clearPadding(byte[] cipherText) {
        byte[] answer = new byte[getBounds(cipherText)];
        for (int i = 0; i < cipherText.length; i++) {
            if (cipherText[i] == 0)
                break;
            answer[i] = cipherText[i];
        }

        return answer;
    }

    /*
     * Funcion: getBounds
     */

    private static int getBounds(byte[] cipherText) {
        for (int i = 0; i < cipherText.length; i++) {
            if (cipherText[i] == 0) {
                return i;
            }
        }
        return cipherText.length;
    }

    /*
     * Funcion: encryptBlock.
     */
    private static byte[] encryptBlock(byte[] plainText) {

        int regA, regB, regC, regD;
        int index = 0, temp1, temp2, swap;

        regA = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8 | (plainText[index++] & 0xff) << 16
                | (plainText[index++] & 0xff) << 24);
        regB = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8 | (plainText[index++] & 0xff) << 16
                | (plainText[index++] & 0xff) << 24);
        regC = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8 | (plainText[index++] & 0xff) << 16
                | (plainText[index++] & 0xff) << 24);
        regD = ((plainText[index++] & 0xff) | (plainText[index++] & 0xff) << 8 | (plainText[index++] & 0xff) << 16
                | (plainText[index++] & 0xff) << 24);

        regB = regB + S[0];
        regD = regD + S[1];

        for (int i = 1; i <= r; i++) {
            temp1 = rotateLeft(regB * (regB * 2 + 1), 5);
            temp2 = rotateLeft(regD * (regD * 2 + 1), 5);
            regA = (rotateLeft(regA ^ temp1, temp2)) + S[i * 2];
            regC = (rotateLeft(regC ^ temp2, temp1)) + S[i * 2 + 1];

            swap = regA;
            regA = regB;
            regB = regC;
            regC = regD;
            regD = swap;
        }

        regA = regA + S[r * 2 + 2];
        regC = regC + S[r * 2 + 3];

        return convertToHex(regA, regB, regC, regD);
    }

    /*
     * Funcion: decryptBlock.
     */

    private static byte[] decryptBlock(byte[] cipherText) {

        int regA, regB, regC, regD;
        int index = 0, temp1, temp2, swap;

        regA = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8 | (cipherText[index++] & 0xff) << 16
                | (cipherText[index++] & 0xff) << 24);
        regB = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8 | (cipherText[index++] & 0xff) << 16
                | (cipherText[index++] & 0xff) << 24);
        regC = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8 | (cipherText[index++] & 0xff) << 16
                | (cipherText[index++] & 0xff) << 24);
        regD = ((cipherText[index++] & 0xff) | (cipherText[index++] & 0xff) << 8 | (cipherText[index++] & 0xff) << 16
                | (cipherText[index++] & 0xff) << 24);

        regC = regC - S[r * 2 + 3];
        regA = regA - S[r * 2 + 2];

        for (int i = r; i >= 1; i--) {
            swap = regD;
            regD = regC;
            regC = regB;
            regB = regA;
            regA = swap;

            temp2 = rotateLeft(regD * (regD * 2 + 1), 5);
            temp1 = rotateLeft(regB * (regB * 2 + 1), 5);
            regC = rotateRight(regC - S[i * 2 + 1], temp1) ^ temp2;
            regA = rotateRight(regA - +S[i * 2], temp2) ^ temp1;
        }

        regD = regD - S[1];
        regB = regB - S[0];
        return convertToHex(regA, regB, regC, regD);
    }

    public String encrypt(byte[] plainText) {
        String result;
        int blocks_number = plainText.length / 16 + 1;
        int block_counter = 0;
        try {
            plainTextLength = plainText.length;
            output = new byte[16 * blocks_number];
            keyShedule(MY_KEY);
            logger.info("Llave generada RC-6");
            for (int i = 0; i < blocks_number; i++) {
                if (blocks_number == i + 1) {
                    mergeArrays(
                            encryptBlock(
                                    fillBufferZeroes(Arrays.copyOfRange(plainText, block_counter, plainText.length))));
                    break;
                }
                mergeArrays(encryptBlock(Arrays.copyOfRange(plainText, block_counter, block_counter + 16)));
                block_counter += 16;
            }
            counter = 0;
            logger.info("RC-6 Bytes: " + output);
            byte[] encoded = Base64Utils.encode(output);
            result = new String(encoded, CHAR_ENCODING);
            return result;
        } catch (Exception e) {
            logger.error("Error: " + e.getMessage());
        }
        return null;
    }

    public String decrypt(byte[] cipherText) {
        String result;
        byte[] decoded = Base64Utils.decode(cipherText);
        int blocks_number = decoded.length / 16 + 1;
        int block_counter = 0;
        try {
            output = new byte[16 * blocks_number];
            keyShedule(MY_KEY);

            for (int i = 0; i < blocks_number; i++) {
                if (blocks_number == i + 1) {
                    mergeArrays(decryptBlock(
                            fillBufferZeroes(Arrays.copyOfRange(decoded, block_counter, decoded.length))));
                    break;
                }
                mergeArrays(decryptBlock(Arrays.copyOfRange(decoded, block_counter, block_counter + 16)));
                block_counter += 16;
            }
            counter = 0;
            output = clearPadding(output);
            logger.info("RC-6 Bytes: " + output);
            result = new String(output, CHAR_ENCODING);
            return result;
        } catch (Exception e) {
            logger.error("Error: " + e.getMessage());
        }
        return null;
    }
    /*
     * Funcion: keyShedule
     */

    private void keyShedule(byte[] key) {
        int bytes = w / 8;
        int c = key.length / bytes;
        int[] L = new int[c];
        int index = 0;

        for (int i = 0; i < c; i++) {
            L[i] = ((key[index++]) & 0xff | (key[index++] & 0xff) << 8 | (key[index++] & 0xff) << 16
                    | (key[index++] & 0xff) << 24);
        }
        S[0] = Pw;

        for (int i = 1; i <= 2 * r + 3; i++) {
            S[i] = S[i - 1] + Qw;
        }

        int A = 0, B = 0, i = 0, j = 0;
        int v = 3 * Math.max(c, 2 * r + 4);

        for (int k = 1; k <= v; k++) {
            A = S[i] = rotateLeft(S[i] + A + B, 3);
            B = L[j] = rotateLeft(L[j] + A + B, A + B);
            i = (i + 1) % (2 * r + 4);
            j = (j + 1) % c;
        }
    }

    public void setKey(String secret) {
        try {
            byte[] key = secret.getBytes("UTF-8");            
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] digestOfPassword = sha.digest(key);
            byte[] keyBytes = Arrays.copyOf(digestOfPassword, RC6_KEYLENGTH);
            secretKey = new SecretKeySpec(keyBytes, ALGORITHM_NAME);
            System.out.println(secretKey.getEncoded());
            logger.info("Clave Generado: " + secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public void encryptFile(File fromFile, File toFile, String clave) throws Exception {
        // read a file
        byte[] fileContent = Files.readAllBytes(fromFile.toPath());
        setKey(clave);
        try {
            Cipher encryptionCipher = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);
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

    public void decryptFile(File fromEncryptedFile, String toFile, String clave) throws Exception {
        // read a file
        byte[] fileContent = Files.readAllBytes(fromEncryptedFile.toPath());
        setKey(clave);
        try {
            Cipher decryptionCipher = Cipher.getInstance(ALGORITHM_NAME + "/" + MODE_OF_OPERATION + "/" + PADDING_SCHEME);
            decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey);
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