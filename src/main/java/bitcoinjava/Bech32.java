package bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static java.math.BigInteger.*;
import static java.util.Objects.isNull;

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
        combinedProgram.addAll(convertBits(witnessProgram, 8, 5, true));
        String result = bech32Encode(hrp, combinedProgram);
        String[] decoded = decode(hrp, result);
        if (isNull(decoded[0]) || isNull(decoded[1])) {
            return null;
        }
        return result;
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

    public static String[] decode(String hrp, String address) {
        Object[] hrpAddress = bech32Decode(address);
        String hrpGot = (String) hrpAddress[0];
        List<Integer> data = (List<Integer>) hrpAddress[1];
        if (!hrpGot.equals(hrp)) {
            return new String[]{null, null};
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        data.subList(1, data.size()).forEach(byteArrayOutputStream::write);

        List<Integer> decoded = convertBits(byteArrayOutputStream.toByteArray(), 5, 8, false);
        if (isNull(decoded) || decoded.size() < 2 || decoded.size() > 40) {
            return new String[]{null, null};
        }
        if (data.get(0) > 16) {
            return new String[]{null, null};
        }
        if (data.get(0) == 0 && decoded.size() != 20 && decoded.size() != 32) {
            return new String[]{null, null};
        }
        ByteArrayOutputStream decodedBytes = new ByteArrayOutputStream();
        decoded.forEach(decodedBytes::write);
        return new String[]{String.valueOf(data.get(0)), Hex.toHexString(decodedBytes.toByteArray())};
    }

    private static Object[] bech32Decode(String address) {
        int position = address.lastIndexOf("1");
        if (!isValidAddress(address, position)) {
            return new Object[]{null, null};
        }

        address = address.toLowerCase();
        String hrp = address.substring(0, position);
        List<Integer> data = new ArrayList<>();
        for (char c : address.substring(position + 1).toCharArray()) {
            data.add(BECH32_ALPHABET.indexOf(c));
        }
        BigInteger spec = verifyChecksum(hrp, data);
        if (isNull(spec)) {
            return new Object[]{null, null};
        }
        return new Object[]{hrp, data.subList(0, data.size() - 6)};
    }

    private static boolean isValidAddress(String address, int position) {
        for (char c : address.toCharArray()) {
            if (c < 33 || c > 126) {
                return false;
            }
        }
        if (position < 1 || position + 7 > address.length() || address.length() > 90) {
            return false;
        }
        return !isMixedCase(address);
    }

    private static BigInteger verifyChecksum(String hrp, List<Integer> data) {
        ArrayList<Integer> combined = new ArrayList<>(hrpExpand(hrp));
        combined.addAll(data);
        if (polymod(combined).equals(ONE)) {
            return ONE;
        }
        return null;
    }

    private static boolean isMixedCase(String address) {
        return !address.toLowerCase().equals(address) && !address.toUpperCase().equals(address);
    }
}
