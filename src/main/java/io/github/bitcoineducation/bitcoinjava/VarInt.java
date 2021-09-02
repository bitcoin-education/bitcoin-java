package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

import static java.math.BigInteger.valueOf;

public class VarInt {
    public static BigInteger fromByteStream(ByteArrayInputStream bytes) throws IOException {
        BigInteger firstByte = new BigInteger(1, bytes.readNBytes(1));
        if (firstByte.equals(valueOf(253))) {
            return LittleEndian.toUnsignedLittleEndian(bytes.readNBytes(2));
        } else if(firstByte.equals(valueOf(254))) {
            return LittleEndian.toUnsignedLittleEndian(bytes.readNBytes(4));
        } else if(firstByte.equals(valueOf(255))) {
            return LittleEndian.toUnsignedLittleEndian(bytes.readNBytes(8));
        }
        return firstByte;
    }

    public static ByteArrayInputStream toByteStream(BigInteger bigInteger) {
        if (bigInteger.compareTo(new BigInteger(1, Hex.decodeStrict("fd"))) < 0) {
            return new ByteArrayInputStream(BigIntegers.asUnsignedByteArray(bigInteger));
        } else if (bigInteger.compareTo(new BigInteger(1, Hex.decodeStrict("010000"))) < 0) {
            return new ByteArrayInputStream(ByteUtils.concatenate(Hex.decodeStrict("fd"), LittleEndian.fromUnsignedLittleEndian(bigInteger, 2)));
        } else if (bigInteger.compareTo(new BigInteger(1, Hex.decodeStrict("0100000000"))) < 0) {
            return new ByteArrayInputStream(ByteUtils.concatenate(Hex.decodeStrict("fe"), LittleEndian.fromUnsignedLittleEndian(bigInteger, 4)));
        } else if (bigInteger.compareTo(new BigInteger(1, Hex.decodeStrict("010000000000000000"))) < 0) {
            return new ByteArrayInputStream(ByteUtils.concatenate(Hex.decodeStrict("ff"), LittleEndian.fromUnsignedLittleEndian(bigInteger, 8)));
        }
        throw new IllegalArgumentException("Number too large: ".concat(bigInteger.toString()));
    }

    public static String toHex(BigInteger bigInteger) {
        return Hex.toHexString(toByteStream(bigInteger).readAllBytes());
    }
}
