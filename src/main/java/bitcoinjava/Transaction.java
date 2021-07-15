package bitcoinjava;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;

import static java.util.Objects.isNull;

public class Transaction {
    private static final String SEGWIT_MARKER = "00";

    private static final String SEGWIT_FLAG = "01";

    private final BigInteger version;

    private final ArrayList<TransactionInput> inputs;

    private final ArrayList<TransactionOutput> outputs;

    private final BigInteger locktime;

    private boolean segwit;

    private String hashPrevOuts;

    private String hashSequence;

    private String hashOutputs;

    private String shaPrevOuts;

    private String shaSequence;

    private String shaOutputs;

    private String shaScriptPubkeys;

    private String shaAmounts;

    public Transaction(BigInteger version, ArrayList<TransactionInput> inputs, ArrayList<TransactionOutput> outputs, BigInteger locktime, boolean segwit) {
        this.version = version;
        this.inputs = inputs;
        this.outputs = outputs;
        this.locktime = locktime;
        this.segwit = segwit;
    }

    public static Transaction fromByteStream(ByteArrayInputStream stream) throws IOException {
        if (isSegwit(stream)) {
            return parseSegwit(stream);
        }
        return parseLegacy(stream);
    }

    private static Transaction parseSegwit(ByteArrayInputStream stream) throws IOException {
        BigInteger version = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(4));
        verifySegwit(stream);
        BigInteger numInputs = VarInt.fromByteStream(stream);
        ArrayList<TransactionInput> inputs = new ArrayList<>();
        for (BigInteger i = BigInteger.ZERO; i.compareTo(numInputs) < 0; i = i.add(BigInteger.ONE)) {
            inputs.add(TransactionInput.fromByteStream(stream));
        }
        BigInteger numOutputs = VarInt.fromByteStream(stream);
        ArrayList<TransactionOutput> outputs = new ArrayList<>();
        for (BigInteger i = BigInteger.ZERO; i.compareTo(numOutputs) < 0; i = i.add(BigInteger.ONE)) {
            outputs.add(TransactionOutput.fromByteStream(stream));
        }
        for (TransactionInput input : inputs) {
            input.setWitnessFromByteStream(stream);
        }
        BigInteger locktime = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(4));
        return new Transaction(version, inputs, outputs, locktime, true);
    }

    private static void verifySegwit(ByteArrayInputStream stream) throws IOException {
        String markerAndFlag = Hex.toHexString(stream.readNBytes(2));
        if (!markerAndFlag.equals(SEGWIT_MARKER.concat(SEGWIT_FLAG))) {
            throw new RuntimeException("Malformed segwit transaction.");
        }
    }

    private static Transaction parseLegacy(ByteArrayInputStream stream) throws IOException {
        BigInteger version = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(4));
        BigInteger numInputs = VarInt.fromByteStream(stream);
        ArrayList<TransactionInput> inputs = new ArrayList<>();
        for (BigInteger i = BigInteger.ZERO; i.compareTo(numInputs) < 0; i = i.add(BigInteger.ONE)) {
            inputs.add(TransactionInput.fromByteStream(stream));
        }
        BigInteger numOutputs = VarInt.fromByteStream(stream);
        ArrayList<TransactionOutput> outputs = new ArrayList<>();
        for (BigInteger i = BigInteger.ZERO; i.compareTo(numOutputs) < 0; i = i.add(BigInteger.ONE)) {
            outputs.add(TransactionOutput.fromByteStream(stream));
        }
        BigInteger locktime = LittleEndian.toUnsignedLittleEndian(stream.readNBytes(4));
        return new Transaction(version, inputs, outputs, locktime, false);
    }

    public String serialize() throws IOException {
        if (segwit) {
            return serializeSegwit();
        }
        return serializeLegacy();
    }

    private String serializeSegwit() throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(version, 4));
        stringBuilder.append(SEGWIT_MARKER.concat(SEGWIT_FLAG));
        stringBuilder.append(VarInt.toHex(BigInteger.valueOf(inputs.size())));
        for (TransactionInput input : inputs) {
            stringBuilder.append(input.serialize());
        }
        stringBuilder.append(VarInt.toHex(BigInteger.valueOf(outputs.size())));
        for (TransactionOutput output : outputs) {
            stringBuilder.append(output.serialize());
        }
        for (TransactionInput input : inputs) {
            stringBuilder.append(input.getWitness().serialize());
        }
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(locktime, 4));
        return stringBuilder.toString();
    }

    private String serializeLegacy() throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(version, 4));
        stringBuilder.append(VarInt.toHex(BigInteger.valueOf(inputs.size())));
        for (TransactionInput input : inputs) {
            stringBuilder.append(input.serialize());
        }
        stringBuilder.append(VarInt.toHex(BigInteger.valueOf(outputs.size())));
        for (TransactionOutput output : outputs) {
            stringBuilder.append(output.serialize());
        }
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(locktime, 4));
        return stringBuilder.toString();
    }

    public String sigHash(int inputIndex, Script scriptPubkey) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(version, 4));
        stringBuilder.append(VarInt.toHex(BigInteger.valueOf(inputs.size())));
        IntStream.range(0, inputs.size()).forEach(i -> {
            if (i == inputIndex) {
                try {
                    stringBuilder.append(
                        new TransactionInput(
                            inputs.get(i).getPreviousTransactionId(),
                            inputs.get(i).getPreviousIndex(),
                            scriptPubkey,
                            inputs.get(i).getSequence()
                        ).serialize()
                    );
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return;
            }
            try {
                stringBuilder.append(
                    new TransactionInput(
                        inputs.get(i).getPreviousTransactionId(),
                        inputs.get(i).getPreviousIndex(),
                        new Script(new ArrayList<>()),
                        inputs.get(i).getSequence()
                    ).serialize()
                );
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        stringBuilder.append(VarInt.toHex(BigInteger.valueOf(outputs.size())));
        outputs.forEach(output -> {
            try {
                stringBuilder.append(output.serialize());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(locktime, 4));
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(SigHashTypes.SIGHASH_ALL, 4));
        String zRaw = stringBuilder.toString();
        return Hash256.hashToHex(zRaw);
    }

    public String sigHashSegwit(int inputIndex, String serializedScriptPubkey, BigInteger amount) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        TransactionInput transactionInput = inputs.get(inputIndex);
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(version, 4));
        hashPrevOutsAndSequences();
        stringBuilder.append(hashPrevOuts);
        stringBuilder.append(hashSequence);
        stringBuilder.append(Bytes.reverseFromHex(transactionInput.getPreviousTransactionId()));
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(transactionInput.getPreviousIndex(), 4));
        stringBuilder.append(serializedScriptPubkey);
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(amount, 8));
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(transactionInput.getSequence(), 4));
        hashOutputs();
        stringBuilder.append(hashOutputs);
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(locktime, 4));
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(SigHashTypes.SIGHASH_ALL, 4));
        String zRaw = stringBuilder.toString();
        return Hash256.hashToHex(zRaw);
    }

    public String sigHashTaproot(int inputIndex, List<String> serializedScriptPubkeys, List<BigInteger> amounts) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("00");
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(version, 4));
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(locktime, 4));
        shaPrevOutsAndSequences();
        stringBuilder.append(shaPrevOuts);
        shaAmounts(amounts);
        stringBuilder.append(shaAmounts);
        shaScriptPubkeys(serializedScriptPubkeys);
        stringBuilder.append(shaScriptPubkeys);
        stringBuilder.append(shaSequence);
        shaOutputs();
        stringBuilder.append(shaOutputs);
        stringBuilder.append("00");
        TransactionInput transactionInput = inputs.get(inputIndex);
        stringBuilder.append(LittleEndian.fromUnsignedLittleEndianToHex(transactionInput.getPreviousIndex(), 4));
        return stringBuilder.toString();
    }

    private void hashOutputs() throws IOException {
        if(isNull(hashOutputs)) {
            StringBuilder allOutputs = new StringBuilder();
            for (TransactionOutput output : outputs) {
                allOutputs.append(output.serialize());
            }
            hashOutputs = Hash256.hashToHex(allOutputs.toString());
        }
    }

    private void hashPrevOutsAndSequences() {
        if(isNull(hashPrevOuts)) {
            StringBuilder allPrevOuts = new StringBuilder();
            StringBuilder allSequences = new StringBuilder();
            inputs.forEach(input -> {
                allPrevOuts.append(Bytes.reverseFromHex(input.getPreviousTransactionId()));
                allPrevOuts.append(LittleEndian.fromUnsignedLittleEndianToHex(input.getPreviousIndex(), 4));
                allSequences.append(LittleEndian.fromUnsignedLittleEndianToHex(input.getSequence(), 4));
            });
            hashPrevOuts = Hash256.hashToHex(allPrevOuts.toString());
            hashSequence = Hash256.hashToHex(allSequences.toString());
        }
    }

    private void shaPrevOutsAndSequences() {
        if(isNull(shaPrevOuts)) {
            StringBuilder allPrevOuts = new StringBuilder();
            StringBuilder allSequences = new StringBuilder();
            inputs.forEach(input -> {
                allPrevOuts.append(Bytes.reverseFromHex(input.getPreviousTransactionId()));
                allPrevOuts.append(LittleEndian.fromUnsignedLittleEndianToHex(input.getPreviousIndex(), 4));
                allSequences.append(LittleEndian.fromUnsignedLittleEndianToHex(input.getSequence(), 4));
            });
            shaPrevOuts = Sha256.hashToHex(allPrevOuts.toString());
            shaSequence = Sha256.hashToHex(allSequences.toString());
        }
    }

    private void shaOutputs() throws IOException {
        if(isNull(shaOutputs)) {
            StringBuilder allOutputs = new StringBuilder();
            for (TransactionOutput output : outputs) {
                allOutputs.append(output.serialize());
            }
            shaOutputs = Sha256.hashToHex(allOutputs.toString());
        }
    }

    private void shaScriptPubkeys(List<String> serializedScriptPubkeys) {
        if(isNull(shaScriptPubkeys)) {
            StringBuilder allScriptPubkeys = new StringBuilder();
            for (String scripts : serializedScriptPubkeys) {
                allScriptPubkeys.append(scripts);
            }
            shaScriptPubkeys = Sha256.hashToHex(allScriptPubkeys.toString());
        }
    }

    private void shaAmounts(List<BigInteger> amounts) {
        if(isNull(shaAmounts)) {
            StringBuilder allAmounts = new StringBuilder();
            for (BigInteger amount : amounts) {
                allAmounts.append(LittleEndian.fromUnsignedLittleEndianToHex(amount, 8));
            }
            shaAmounts = Sha256.hashToHex(allAmounts.toString());
        }
    }

    public BigInteger getVersion() {
        return version;
    }

    public ArrayList<TransactionInput> getInputs() {
        return inputs;
    }

    public ArrayList<TransactionOutput> getOutputs() {
        return outputs;
    }

    public BigInteger getLocktime() {
        return locktime;
    }

    public boolean isSegwit() {
        return segwit;
    }

    public void setSegwit(boolean segwit) {
        this.segwit = segwit;
    }

    public static boolean isSegwit(ByteArrayInputStream stream) throws IOException {
        stream.readNBytes(4);
        byte[] marker = stream.readNBytes(1);
        stream.reset();
        return Hex.toHexString(marker).equals(SEGWIT_MARKER);
    }

}
