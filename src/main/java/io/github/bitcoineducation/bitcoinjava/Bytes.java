package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;

public class Bytes {
    public static byte[] reverse(byte[] bytes) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        for (int i = bytes.length - 1; i >= 0; i--) {
            byteArrayOutputStream.write(bytes[i]);
        }
        return byteArrayOutputStream.toByteArray();
    }

    public static String reverseFromHex(String hex) {
        return Hex.toHexString(reverse(Hex.decodeStrict(hex)));
    }

    public static String reverseToHex(byte[] bytes) {
        return Hex.toHexString(reverse(bytes));
    }
}
