package com.example.restapi.springbootapp.utils;

import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.nio.charset.*;
import javax.crypto.spec.*;
import java.security.spec.*;

public class EncriptadorMD5 {

    private final char[] secretKey;
    private final byte[] salt;
    private final int iterations;

    public EncriptadorMD5() {
        this("CEC278B6B50A");
    }

    public EncriptadorMD5(String secretKey) {
        this(secretKey, "DHASJ8347FURYR827486SD");
    }

    public EncriptadorMD5(String secretKey, String salt) {
        this(secretKey, salt, 20);
    }

    public EncriptadorMD5(String secretKey, String salt, int iterations) {
        this.secretKey = secretKey.toCharArray();
        this.salt = Arrays.copyOf(salt.toString().getBytes(Charset.forName("UTF-8")), 8);
        this.iterations = iterations;
    }

    public static String encrypt(String text, String secretKey, String salt, int iterations)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException,
            BadPaddingException {
        return new EncriptadorMD5(secretKey, salt, iterations).encode(text);
    }

    public static String decrypt(String text, String secretKey, String salt, int iterations)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException,
            InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException,
            BadPaddingException {
        return new EncriptadorMD5(secretKey, salt, iterations).decode(text);
    }

    public String encode(final String string) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException,
            UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] bytes;
        if (string != null)
            bytes = string.getBytes(Charset.forName("UTF-8"));
        else
            bytes = new byte[0];
        final SecretKey generateSecret = SecretKeyFactory.getInstance("PBEWithMD5AndDES")
                .generateSecret(new PBEKeySpec(secretKey));
        final Cipher instance = Cipher.getInstance("PBEWithMD5AndDES");
        instance.init(1, generateSecret, new PBEParameterSpec(salt, iterations));
        return new String(a(instance.doFinal(bytes)).getBytes(), "utf-8");
    }

    public String decode(final String string) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException,
            UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        byte[] bytes;
        if (string != null)
            bytes = a(string);
        else
            bytes = new byte[0];
        final SecretKey generateSecret = SecretKeyFactory.getInstance("PBEWithMD5AndDES")
                .generateSecret(new PBEKeySpec(secretKey));
        final Cipher instance = Cipher.getInstance("PBEWithMD5AndDES");
        instance.init(2, generateSecret, new PBEParameterSpec(salt, iterations));
        return new String(instance.doFinal(bytes), "utf-8");
    }

    private String a(final byte[] array) {
        int i = 0;
        String str;
        if (array == null)
            str = null;
        else {
            final byte[] array2 = new byte[array.length + 2];
            System.arraycopy(array, 0, array2, 0, array.length);
            final byte[] array3 = new byte[array2.length / 3 * 4];
            for (int n = 0, j = 0; j < array.length; j += 3, n += 4) {
                array3[n] = (byte) (array2[j] >>> 2 & 0x3F);
                array3[n + 1] = (byte) ((array2[j + 1] >>> 4 & 0xF) | (array2[j] << 4 & 0x3F));
                array3[n + 2] = (byte) ((array2[j + 2] >>> 6 & 0x3) | (array2[j + 1] << 2 & 0x3F));
                array3[n + 3] = (byte) (array2[j + 2] & 0x3F);
            }
            while (i < array3.length) {
                if (array3[i] < 26)
                    array3[i] += 65;
                else if (array3[i] < 52)
                    array3[i] = (byte) (array3[i] + 97 - 26);
                else if (array3[i] < 62)
                    array3[i] = (byte) (array3[i] + 48 - 52);
                else if (array3[i] < 63)
                    array3[i] = 43;
                else
                    array3[i] = 47;
                ++i;
            }
            for (int k = array3.length - 1; k > array.length * 4 / 3; --k)
                array3[k] = 61;
            str = new String(array3);
        }
        return str;
    }

    private byte[] a(final String str) {
        return str == null ? null : b(str.getBytes());
    }

    private byte[] b(final byte[] array) {
        final byte b = 61;
        int i = 0;
        int length;
        for (length = array.length; array[length - 1] == b; --length) {
        }
        final byte[] array2 = new byte[length - array.length / 4];
        for (int j = 0; j < array.length; ++j) {
            if (array[j] == b)
                array[j] = 0;
            else if (array[j] == 47)
                array[j] = 63;
            else if (array[j] == 43)
                array[j] = 62;
            else if (array[j] >= 48 && array[j] <= 57)
                array[j] += 4;
            else if (array[j] >= 97 && array[j] <= 122)
                array[j] -= 71;
            else if (array[j] >= 65 && array[j] <= 90)
                array[j] -= 65;
        }
        int n = 0;
        while (i < array2.length - 2) {
            array2[i] = (byte) ((array[n] << 2 & 0xFF) | (array[n + 1] >>> 4 & 0x3));
            array2[i + 1] = (byte) ((array[n + 1] << 4 & 0xFF) | (array[n + 2] >>> 2 & 0xF));
            array2[i + 2] = (byte) ((array[n + 2] << 6 & 0xFF) | (array[n + 3] & 0x3F));
            n += 4;
            i += 3;
        }
        if (i < array2.length)
            array2[i] = (byte) ((array[n] << 2 & 0xFF) | (array[n + 1] >>> 4 & 0x3));
        final int n2 = i + 1;
        if (n2 < array2.length)
            array2[n2] = (byte) ((array[n + 2] >>> 2 & 0xF) | (array[n + 1] << 4 & 0xFF));
        return array2;
    }
}
