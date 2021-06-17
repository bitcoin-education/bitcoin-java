package bitcoinjava;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

public class LittleEndian {
    public static BigInteger toUnsignedLittleEndian(byte[] bytes) {
        return new BigInteger(1, Bytes.reverse(bytes));
    }

    public static byte[] fromUnsignedLittleEndian(BigInteger bigInteger, int outputLength) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(outputLength, bigInteger);
        return Bytes.reverse(bytes);
    }

    public static String fromUnsignedLittleEndianToHex(BigInteger bigInteger, int outputLength) {
        return Hex.toHexString(fromUnsignedLittleEndian(bigInteger, outputLength));
    }
}
