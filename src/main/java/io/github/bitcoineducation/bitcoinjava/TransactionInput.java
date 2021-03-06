package io.github.bitcoineducation.bitcoinjava;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;

import static io.github.bitcoineducation.bitcoinjava.OpCodes.OP_0;
import static java.math.BigInteger.valueOf;
import static java.util.Objects.isNull;

public class TransactionInput {
    private final String previousTransactionId;

    private final BigInteger previousIndex;

    private Script scriptSig;

    private final BigInteger sequence;

    private Witness witness = new Witness(new ArrayList<>());

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

    public void appendToP2SHScriptSig(Object command) {
        if (isNull(scriptSig) || scriptSig.getCommands().size() == 0) {
            scriptSig = new Script(new ArrayList<>());
            scriptSig.appendCommand(valueOf(OP_0));
        }
        scriptSig.appendCommand(command);
    }

    public Witness getWitness() {
        return witness;
    }

    public void setWitness(Witness witness) {
        this.witness = witness;
    }

    public void appendToWitness(Object command) {
        if (witness.getItems().size() == 0) {
            witness.appendItem(valueOf(OP_0));
        }
        witness.appendItem(command);
    }
}
