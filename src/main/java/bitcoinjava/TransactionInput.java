package bitcoinjava;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

public class TransactionInput {
    private final String previousTransactionId;

    private final BigInteger previousIndex;

    private Script scriptSig;

    private final BigInteger sequence;

    private Witness witness = new Witness(List.of());

    public TransactionInput(String previousTransactionId, BigInteger previousIndex, Script scriptSig, BigInteger sequence) {
        this.previousTransactionId = previousTransactionId;
        this.previousIndex = previousIndex;
        this.scriptSig = scriptSig;
        this.sequence = sequence;
    }

    public static TransactionInput fromByteStream(ByteArrayInputStream stream) throws IOException {
        String previousTransactionId = Bytes.reverseToHex(stream.readNBytes(32));
        BigInteger previousIndex = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(4));
        Script scriptSig = Script.fromByteStream(stream);
        BigInteger sequence = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(4));
        return new TransactionInput(previousTransactionId, previousIndex, scriptSig, sequence);
    }

    public void setWitnessFromByteStream(ByteArrayInputStream stream) throws IOException {
        witness = Witness.fromByteStream(stream);
    }

    public String serialize() throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(Bytes.reverseFromHex(previousTransactionId));
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(previousIndex, 4));
        stringBuilder.append(scriptSig.serialize());
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(sequence, 4));
        return stringBuilder.toString();
    }

    public String getPreviousTransactionId() {
        return previousTransactionId;
    }

    public BigInteger getPreviousIndex() {
        return previousIndex;
    }

    public Script getScriptSig() {
        return scriptSig;
    }

    public BigInteger getSequence() {
        return sequence;
    }

    public void setScriptSig(Script scriptSig) {
        this.scriptSig = scriptSig;
    }

    public Witness getWitness() {
        return witness;
    }

    public void setWitness(Witness witness) {
        this.witness = witness;
    }

}
