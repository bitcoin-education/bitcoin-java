package io.github.bitcoineducation.bitcoinjava;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class TransactionOutput {
    private final BigInteger amount;

    private final Script scriptPubkey;

    public TransactionOutput(BigInteger amount, Script scriptPubkey) {
        this.amount = amount;
        this.scriptPubkey = scriptPubkey;
    }

    public static TransactionOutput fromByteStream(ByteArrayInputStream stream) throws IOException {
        BigInteger amount = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(8));
        Script scriptPubkey = Script.fromByteStream(stream);
        return new TransactionOutput(amount, scriptPubkey);
    }

    public String serialize() throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(amount, 8));
        stringBuilder.append(scriptPubkey.serialize());
        return stringBuilder.toString();
    }

    public BigInteger getAmount() {
        return amount;
    }

    public Script getScriptPubkey() {
        return scriptPubkey;
    }
}
