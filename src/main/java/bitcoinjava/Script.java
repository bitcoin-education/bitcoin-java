package bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static java.math.BigInteger.*;

public class Script {

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

    public static Script p2pkhScript(String hash160Pubkey) {
        return new Script(List.of(valueOf(OpCodes.OP_DUP), valueOf(OpCodes.OP_HASH160), hash160Pubkey, valueOf(OpCodes.OP_EQUALVERIFY), valueOf(OpCodes.OP_CHECKSIG)));
    }

    public static Script p2wpkhScript(String hash160Pubkey) {
        return new Script(List.of(ZERO, hash160Pubkey));
    }

    public static Script p2shScript(String hash160) {
        return new Script(List.of(valueOf(OpCodes.OP_HASH160), hash160, valueOf(OpCodes.OP_EQUAL)));
    }

}
