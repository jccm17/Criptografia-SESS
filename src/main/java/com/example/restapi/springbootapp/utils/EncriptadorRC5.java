package com.example.restapi.springbootapp.utils;

import java.io.*;

public class EncriptadorRC5 {

    public void encrypt() throws Exception {
        KeyExp ke = new KeyExp();
        String s[] = ke.compute();
        System.out.println("Enter Input");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("a = ");
        String a = fullfill0(Long.toBinaryString(Long.parseLong(br.readLine(), 16)));
        System.out.print("b = ");
        String b = fullfill0(Long.toBinaryString(Long.parseLong(br.readLine(), 16)));
        a = add(a, fullfill0(s[0]));
        b = add(b, fullfill0(s[1]));
        int tmp = 0;
        for (int i = 1; i <= 12; i++) {
            tmp = Integer.parseInt("" + Long.parseLong(b, 2) % 32);
            a = xor(a, b);
            a = a.substring(tmp) + a.substring(0, tmp);
            a = add(a, fullfill0(s[2 * i]));
            tmp = Integer.parseInt("" + Long.parseLong(a, 2) % 32);
            b = xor(b, a);
            b = b.substring(tmp) + b.substring(0, tmp);
            b = add(b, fullfill0(s[(2 * i) + 1]));
            System.out.println(i + " iteration = " + (Long.toHexString(Long.parseLong(a, 2)))
                    + (Long.toHexString(Long.parseLong(b, 2))));
        }
        String out = a + b;
        System.out.println("Output = " + (Long.toHexString(Long.parseLong((out.substring(0, 32)), 2)))
                + (Long.toHexString(Long.parseLong((out.substring(32)), 2))));
    }

    public void decrypt() throws Exception {
        KeyExp ke = new KeyExp();
        String s[] = ke.compute();
        System.out.println("Enter Input");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("a = ");
        String a = fullfill0(Long.toBinaryString(Long.parseLong(br.readLine(), 16)));
        System.out.print("b = ");
        String b = fullfill0(Long.toBinaryString(Long.parseLong(br.readLine(), 16)));
        int tmp = 0;
        for (int i = 12; i >= 1; i--) {
            b = fullfill0(Long.toBinaryString((Long.parseLong(b, 2) - Long.parseLong(s[(2 * i) + 1], 2))));
            b = b.substring(b.length() - 32);
            tmp = Integer.parseInt("" + Long.parseLong(a, 2) % 32);
            b = b.substring(b.length() - tmp) + b.substring(0, b.length() - tmp);
            b = xor(b, a);
            a = fullfill0(Long.toBinaryString((Long.parseLong(a, 2) - Long.parseLong(s[2 * i], 2))));
            a = a.substring(a.length() - 32);
            tmp = Integer.parseInt("" + Long.parseLong(b, 2) % 32);
            a = a.substring(a.length() - tmp) + a.substring(0, a.length() - tmp);
            a = xor(a, b);
            System.out.println(i + " iteration = " + (Long.toHexString(Long.parseLong(a, 2)))
                    + (Long.toHexString(Long.parseLong(b, 2))));
        }
        a = fullfill0(Long.toBinaryString((Long.parseLong(a, 2) - Long.parseLong(s[0], 2))));
        b = fullfill0(Long.toBinaryString((Long.parseLong(b, 2) - Long.parseLong(s[1], 2))));
        String output = a + b;
        output = output.substring(output.length() - 64);
        System.out.println("Output = " + (Long.toHexString(Long.parseLong(output.substring(0, 32), 2)))
                + (Long.toHexString(Long.parseLong(output.substring(32), 2))));
    }

    public String fullfill0(String x) {
        return (get0(32 - x.length()) + x);
    }

    public String xor(String x, String y) {
        String result = "";
        for (int i = 0; i < x.length(); i++) {
            if (x.charAt(i) == y.charAt(i)) {
                result += "0";
            } else {
                result += "1";
            }

        }
        return result;
    }

    public String get0(int len) {
        String result = "";
        for (int i = 0; i < len; i++) {
            result += "0";
        }
        return result;
    }

    public String add(String x, String y) {
        String result = "";
        boolean carry = false;
        for (int i = x.length() - 1; i >= 0; i--) {
            if ((x.charAt(i) == y.charAt(i) && carry == false) || (x.charAt(i) != y.charAt(i) && carry == true)) {
                result = "0" + result;
            } else {
                result = "1" + result;
            }
            if ((x.charAt(i) == '1' && y.charAt(i) == '1') ||
                    (x.charAt(i) == '1' && y.charAt(i) == '1' && carry == true) ||
                    (x.charAt(i) != y.charAt(i) && carry == true)) {
                carry = true;
            } else {
                carry = false;
            }
        }
        return result;
    }
}
