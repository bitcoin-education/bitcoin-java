package bitcoinjava;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static java.math.BigInteger.*;

public class BitsConverter {
    public static List<Integer> convertBits(byte[] key, int fromBits, int toBits, boolean pad) {
        BigInteger acc = ZERO;
        BigInteger bits = ZERO;
        List<Integer> result = new ArrayList<>();
        BigInteger maxValue = ONE.shiftLeft(toBits).subtract(ONE);
        BigInteger maxAcc = ONE.shiftLeft(fromBits + toBits - 1).subtract(ONE);
        for (byte b : key) {
            int bi = Byte.toUnsignedInt(b);
            if (bi >> fromBits != 0) {
                return null;
            }
            acc = acc.shiftLeft(fromBits).xor(valueOf(bi)).and(maxAcc);
            bits = bits.add(valueOf(fromBits));
            while (bits.compareTo(valueOf(toBits)) >= 0) {
                bits = bits.subtract(valueOf(toBits));
                result.add(acc.shiftRight(bits.intValueExact()).and(maxValue).intValueExact());
            }
        }
        if (pad && !bits.equals(ZERO)) {
            result.add(acc.shiftLeft(toBits - bits.intValueExact()).and(maxValue).intValueExact());
        }
        if (!pad && (bits.compareTo(valueOf(fromBits)) >= 0 || !acc.shiftLeft(valueOf(toBits).subtract(bits).intValueExact()).and(maxValue).equals(ZERO))) {
            return null;
        }
        return result;
    }
}
