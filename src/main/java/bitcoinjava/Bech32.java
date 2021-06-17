package bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static java.math.BigInteger.*;

public class Bech32 {

    private static final String BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    public static List<Integer> createChecksum(String hrp, List<Integer> data) {
        List<Integer> values = new ArrayList<>(hrpExpand(hrp));
        values.addAll(data);
        values.addAll(List.of(0, 0, 0, 0, 0, 0));
        BigInteger polymod = polymod(values).xor(ONE);
        List<Integer> checksum = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            checksum.add((polymod.shiftRight(valueOf(5).multiply(valueOf(5).subtract(valueOf(i))).intValueExact())).and(valueOf(31)).intValueExact());
        }
        return checksum;
    }

    public static List<Integer> hrpExpand(String hrp) {
        List<Integer> list = new ArrayList<>();
        for (char c : hrp.toCharArray()) {
            list.add(c >> 5);
        }
        list.add(0);
        for (char c : hrp.toCharArray()) {
            list.add(c & 31);
        }
        return list;
    }

    public static List<Integer> convertBits(byte[] key) {
        BigInteger acc = ZERO;
        BigInteger bits = ZERO;
        List<Integer> result = new ArrayList<>();
        BigInteger maxValue = ONE.shiftLeft(5).subtract(ONE);
        BigInteger maxAcc = ONE.shiftLeft(8 + 5 - 1).subtract(ONE);
        for (byte b : key) {
            int bi = Byte.toUnsignedInt(b);
            if (bi >> 8 != 0) {
                return null;
            }
            acc = acc.shiftLeft(8).xor(valueOf(bi)).and(maxAcc);
            bits = bits.add(valueOf(8));
            while (bits.compareTo(valueOf(5)) >= 0) {
                bits = bits.subtract(valueOf(5));
                result.add(acc.shiftRight(bits.intValueExact()).and(maxValue).intValueExact());
            }
        }
        if (!bits.equals(ZERO)) {
            result.add(acc.shiftLeft(5 - bits.intValueExact()).and(maxValue).intValueExact());
        }
        return result;
    }

    public static BigInteger polymod(List<Integer> values) {
        BigInteger[] generator = new BigInteger[]{
            new BigInteger(1, Hex.decode("3b6a57b2")),
            new BigInteger(1, Hex.decode("26508e6d")),
            new BigInteger(1, Hex.decode("1ea119fa")),
            new BigInteger(1, Hex.decode("3d4233dd")),
            new BigInteger(1, Hex.decode("2a1462b3"))
        };
        BigInteger checksum = ONE;
        for (Integer value : values) {
           BigInteger top = checksum.shiftRight(25);
           checksum = checksum.and(new BigInteger(1, Hex.decode("01ffffff"))).shiftLeft(5).xor(valueOf(value));
            for (int i = 0; i < 5; i++) {
                if (!top.shiftRight(i).and(ONE).equals(ZERO)) {
                    checksum = checksum.xor(generator[i]);
                } else {
                    checksum = checksum.xor(ZERO);
                }
            }
        }
        return checksum;
    }

    /*
    Compatible only with witness version 0 for now
     */
    public static String encode(String hrp, int witnessVersion, byte[] witnessProgram) {
        ArrayList<Integer> combinedProgram = new ArrayList<>();
        combinedProgram.add(witnessVersion);
        combinedProgram.addAll(convertBits(witnessProgram));
        return bech32Encode(hrp, combinedProgram);
    }

    private static String bech32Encode(String hrp, ArrayList<Integer> combinedProgram) {
        ArrayList<Integer> combined = new ArrayList<>(combinedProgram);
        combined.addAll(createChecksum(hrp, combinedProgram));
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(hrp);
        stringBuilder.append("1");
        for (Integer i : combined) {
            stringBuilder.append(BECH32_ALPHABET.charAt(i));
        }
        return stringBuilder.toString();
    }

}
