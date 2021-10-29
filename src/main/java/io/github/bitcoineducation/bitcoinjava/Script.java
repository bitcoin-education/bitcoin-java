package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.math.BigInteger.*;

public class Script {

    public static final String UNKNOWN = "UNKNOWN";
    public static final String P2PKH = "P2PKH";
    public static final String P2SH = "P2SH";
    public static final String P2WPKH = "P2WPKH";
    public static final String P2WSH = "P2WSH";
    public static final String P2TR = "P2TR";

    private final List<Object> commands;

    public Script(List<Object> commands) {
        this.commands = commands;
    }

    public static Script fromByteStream(ByteArrayInputStream stream) throws IOException {
        BigInteger length = VarInt.fromByteStream(stream);
        ArrayList<Object> commands = new ArrayList<>();
        BigInteger count = BigInteger.ZERO;
        while (count.compareTo(length) < 0) {
            BigInteger current = new BigInteger(1, stream.readNBytes(1));
            count = count.add(BigInteger.ONE);

            if (current.compareTo(BigInteger.ONE) >= 0 && current.compareTo(valueOf(75)) <= 0) {
                commands.add(Hex.toHexString(stream.readNBytes(current.intValueExact())));
                count = count.add(current);
            } else if(current.equals(valueOf(76))) {
                BigInteger dataLength = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(1));
                commands.add(Hex.toHexString(stream.readNBytes(dataLength.intValueExact())));
                count = count.add(dataLength.add(BigInteger.ONE));
            } else if(current.equals(valueOf(77))) {
                BigInteger dataLength = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(2));
                commands.add(Hex.toHexString(stream.readNBytes(dataLength.intValueExact())));
                count = count.add(dataLength.add(BigInteger.TWO));
            } else {
                commands.add(current);
            }
        }
        if (!count.equals(length)) {
            throw new RuntimeException("Parsing script failed");
        }
        return new Script(commands);
    }

    public String rawSerialize() {
        StringBuilder stringBuilder = new StringBuilder();
        commands.forEach(command -> {
            if (command instanceof BigInteger) {
                stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex((BigInteger) command, 1));
                return;
            }
            int length = ((String) command).length() / 2;
            if (length < 75) {
                stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(valueOf(length), 1));
            } else if (length > 75 && length <= 255) {
                stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(valueOf(76), 1));
                stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(valueOf(length), 1));
            } else if (length >= 256 && length <= 520) {
                stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(valueOf(77), 1));
                stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(valueOf(length), 2));
            } else {
                throw new RuntimeException("Command too long");
            }
            stringBuilder.append(command);
        });
        return stringBuilder.toString();
    }

    public String rawSerializeForSegwitSigHash() {
        StringBuilder stringBuilder = new StringBuilder();
        commands.forEach(command -> {
            if (command instanceof BigInteger) {
                stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex((BigInteger) command, 1));
                return;
            }
            stringBuilder.append(command);
        });
        return stringBuilder.toString();
    }

    public String serialize() throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        String rawSerialized = rawSerialize();
        BigInteger length = valueOf(rawSerialized.length()).divide(BigInteger.TWO);
        return stringBuilder
            .append(VarInt.toHex(length))
            .append(rawSerialized)
            .toString();
    }

    public String serializeForSegwitSigHash() {
        StringBuilder stringBuilder = new StringBuilder();
        String rawSerialized = rawSerializeForSegwitSigHash();
        BigInteger length = valueOf(rawSerialized.length()).divide(BigInteger.TWO);
        return stringBuilder
            .append(VarInt.toHex(length))
            .append(rawSerialized)
            .toString();
    }

    public List<Object> getCommands() {
        return commands;
    }

    public String p2pkhAddress(String prefix) {
        return Base58.encodeWithChecksumFromHex(prefix.concat((String) commands.get(2)));
    }

    public String p2wpkhAddress(String prefix) {
        return Bech32.encode(prefix, 0, Hex.decodeStrict((String) commands.get(1)));
    }

    public String p2trAddress(String prefix) {
        return Bech32.encode(prefix, 1, Hex.decodeStrict((String) commands.get(1)));
    }

    public String p2shAddress(String prefix) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decodeStrict(prefix));
        byteArrayOutputStream.writeBytes(Hex.decode(Hash160.hashToHex(Hex.decode(rawSerialize()))));
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    public String p2wshAddress(String prefix) {
        return Bech32.encode(prefix, 0, Sha256.hash(Hex.decode(rawSerialize())));
    }

    public static Script p2pkhScript(String hash160Pubkey) {
        return new Script(List.of(valueOf(OpCodes.OP_DUP), valueOf(OpCodes.OP_HASH160), hash160Pubkey, valueOf(OpCodes.OP_EQUALVERIFY), valueOf(OpCodes.OP_CHECKSIG)));
    }

    public static Script p2wpkhScript(String hash160Pubkey) {
        return new Script(List.of(ZERO, hash160Pubkey));
    }

    public static Script p2trScript(String outputKey) {
        return new Script(List.of(valueOf(OpCodes.OP_1), outputKey));
    }

    public static Script p2wshScript(String sha256) {
        return new Script(List.of(valueOf(OpCodes.OP_0), sha256));
    }

    public static Script p2shScript(String hash160) {
        return new Script(Arrays.asList(valueOf(OpCodes.OP_HASH160), hash160, valueOf(OpCodes.OP_EQUAL)));
    }

    public void appendCommand(Object command) {
        commands.add(command);
    }

    public String getType() {
        String rawSerialized = rawSerialize();
        BigInteger length = valueOf(rawSerialized.length()).divide(BigInteger.TWO);

        switch (length.intValueExact()) {
            case 25 -> {
                if (isP2PKH()) {
                    return P2PKH;
                }
                return UNKNOWN;
            }
            case 23 -> {
                if (isP2SH()) {
                    return P2SH;
                }
                return UNKNOWN;
            }
            case 22 -> {
                if (isP2WPKH()) {
                    return P2WPKH;
                }
                return UNKNOWN;
            }
            case 34 -> {
                if (isP2WSH()) {
                    return P2WSH;
                }
                if (isP2TR()) {
                    return P2TR;
                }
                return UNKNOWN;
            }
            default -> {
                return UNKNOWN;
            }
        }
    }

    private boolean isP2TR() {
        return commands.get(0).equals(valueOf(OpCodes.OP_1)) &&
            ((String)commands.get(1)).length() == 64;
    }

    private boolean isP2WSH() {
        return commands.get(0).equals(valueOf(OpCodes.OP_0)) &&
            ((String)commands.get(1)).length() == 64;
    }

    private boolean isP2WPKH() {
        return commands.get(0).equals(valueOf(OpCodes.OP_0)) &&
            ((String)commands.get(1)).length() == 40;
    }

    private boolean isP2SH() {
        return commands.get(0).equals(valueOf(OpCodes.OP_HASH160)) &&
            ((String)commands.get(1)).length() == 40 &&
            commands.get(2).equals(valueOf(OpCodes.OP_EQUAL));
    }

    private boolean isP2PKH() {
        return commands.get(0).equals(valueOf(OpCodes.OP_DUP)) &&
            commands.get(1).equals(valueOf(OpCodes.OP_HASH160)) &&
            ((String)commands.get(2)).length() == 40 &&
            commands.get(3).equals(valueOf(OpCodes.OP_EQUALVERIFY)) &&
            commands.get(4).equals(valueOf(OpCodes.OP_CHECKSIG));
    }
}
