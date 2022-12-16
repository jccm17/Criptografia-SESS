package com.example.restapi.springbootapp.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypt/Decrypt data by using Blowfish
 * 
 * @author Jccm.17
 */
public class Blowfish {

    private static byte[] key = { 0x11, 0x22, 0x33, 0x44 };

    public void encrypt(byte[] input, byte[] output) throws Exception {
        crypt(Cipher.ENCRYPT_MODE, input, output);
    }

    public void decrypt(byte[] input, byte[] output) throws Exception {
        crypt(Cipher.DECRYPT_MODE, input, output);
    }

    private static void crypt(int opmode, byte[] input, byte[] output) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "Blowfish");
        cipher.init(opmode, keySpec);
        cipher.doFinal(input, 0, input.length, output);
    }
}
