import bitcoinjava.*;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static bitcoinjava.OpCodes.*;
import static java.math.BigInteger.ZERO;
import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class TransactionTest {
    @ParameterizedTest
    @MethodSource("testParameters")
    public void parseVersion(String txHex) throws IOException {
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(BigInteger.ONE, transaction.getVersion());
    }

    @Test
    public void parseInputs() throws IOException {
        String txHex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(1, transaction.getInputs().size());
        String expectedPreviousTx = "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81";
        assertEquals(expectedPreviousTx, transaction.getInputs().get(0).getPreviousTransactionId());
        assertEquals(ZERO, transaction.getInputs().get(0).getPreviousIndex());
        String expectedScriptSig = "6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a";
        assertEquals(expectedScriptSig, transaction.getInputs().get(0).getScriptSig().serialize());
        assertEquals(transaction.getInputs().get(0).getSequence(), BigIntegers.fromUnsignedByteArray(Hex.decode("fffffffe")));
    }

    @Test
    public void parseInputsSegwit() throws IOException {
        String txHex = "01000000000101076b57644e155af90f5d9f416b44a3794e0b982c2c427f0845c0e0c62fbb346f0000000000fdffffff0198eb100000000000160014934478b061fa4b5b4dba4f314fb380f3ef77e21902483045022100b7fcf54ae5d7c645b5b44ef7f846e95de9a97a099a447bf8daf14a46f5e3d464022025e709d6794a6fd5b69a7d271fc9a93fcc170b38cfbe5640b6c5d6ec88f021240121025330a1df68c516d32a87ea8ea3da573fa9d86b1b173875beecbf0bdbe45cba8cea7c0a00";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(1, transaction.getInputs().size());
        String expectedPreviousTx = "6f34bb2fc6e0c045087f422c2c980b4e79a3446b419f5d0ff95a154e64576b07";
        assertEquals(expectedPreviousTx, transaction.getInputs().get(0).getPreviousTransactionId());
        assertEquals(ZERO, transaction.getInputs().get(0).getPreviousIndex());
        String expectedScriptSig = "00";
        assertEquals(expectedScriptSig, transaction.getInputs().get(0).getScriptSig().serialize());
        assertEquals(transaction.getInputs().get(0).getSequence(), BigIntegers.fromUnsignedByteArray(Hex.decode("fffffffd")));
        String expectedWitness = "02483045022100b7fcf54ae5d7c645b5b44ef7f846e95de9a97a099a447bf8daf14a46f5e3d464022025e709d6794a6fd5b69a7d271fc9a93fcc170b38cfbe5640b6c5d6ec88f021240121025330a1df68c516d32a87ea8ea3da573fa9d86b1b173875beecbf0bdbe45cba8c";
        assertEquals(expectedWitness, transaction.getInputs().get(0).getWitness().serialize());
    }

    @Test
    public void parseOutputs() throws IOException {
        String txHex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(2, transaction.getOutputs().size());
        BigInteger expectedAmount = valueOf(32454049);
        assertEquals(expectedAmount, transaction.getOutputs().get(0).getAmount());
        String expectedScriptPubkey = "1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac";
        assertEquals(expectedScriptPubkey, transaction.getOutputs().get(0).getScriptPubkey().serialize());
        BigInteger expectedAmount2 = valueOf(10011545);
        assertEquals(expectedAmount2, transaction.getOutputs().get(1).getAmount());
        String expectedScriptPubkey2 = "1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac";
        assertEquals(expectedScriptPubkey2, transaction.getOutputs().get(1).getScriptPubkey().serialize());
    }

    @Test
    public void parseOutputsSegwit() throws IOException {
        String txHex = "01000000000101076b57644e155af90f5d9f416b44a3794e0b982c2c427f0845c0e0c62fbb346f0000000000fdffffff0198eb100000000000160014934478b061fa4b5b4dba4f314fb380f3ef77e21902483045022100b7fcf54ae5d7c645b5b44ef7f846e95de9a97a099a447bf8daf14a46f5e3d464022025e709d6794a6fd5b69a7d271fc9a93fcc170b38cfbe5640b6c5d6ec88f021240121025330a1df68c516d32a87ea8ea3da573fa9d86b1b173875beecbf0bdbe45cba8cea7c0a00";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(1, transaction.getOutputs().size());
        BigInteger expectedAmount = valueOf(1_108_888);
        assertEquals(expectedAmount, transaction.getOutputs().get(0).getAmount());
        String expectedScriptPubkey = "160014934478b061fa4b5b4dba4f314fb380f3ef77e219";
        assertEquals(expectedScriptPubkey, transaction.getOutputs().get(0).getScriptPubkey().serialize());
    }

    @Test
    public void parseLocktime() throws IOException {
        String txHex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        BigInteger expectedLocktime = valueOf(410393);
        assertEquals(expectedLocktime, transaction.getLocktime());
    }

    @Test
    public void parseLocktimeSegwit() throws IOException {
        String txHex = "01000000000101076b57644e155af90f5d9f416b44a3794e0b982c2c427f0845c0e0c62fbb346f0000000000fdffffff0198eb100000000000160014934478b061fa4b5b4dba4f314fb380f3ef77e21902483045022100b7fcf54ae5d7c645b5b44ef7f846e95de9a97a099a447bf8daf14a46f5e3d464022025e709d6794a6fd5b69a7d271fc9a93fcc170b38cfbe5640b6c5d6ec88f021240121025330a1df68c516d32a87ea8ea3da573fa9d86b1b173875beecbf0bdbe45cba8cea7c0a00";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        BigInteger expectedLocktime = valueOf(687338);
        assertEquals(expectedLocktime, transaction.getLocktime());
    }

    @Test
    public void serialize() throws IOException {
        String txHex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(txHex, transaction.serialize());
    }

    @Test
    public void serialize2() throws IOException, NoSuchAlgorithmException {
        TransactionInput transactionInput = new TransactionInput(
            "d6f72aab8ff86ff6289842a0424319bf2ddba85dc7c52757912297f948286389",
            ZERO,
            new Script(new ArrayList<>()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        TransactionOutput transactionOutput = new TransactionOutput(valueOf(1_000_000), Script.p2shScript(Base58.decodeWithChecksumToHex("3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC")));

        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput);

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, false);

        assertEquals("010000000189632848f99722915727c5c75da8db2dbf194342a0429828f66ff88fab2af7d60000000000ffffffff0140420f000000000017a914f815b036d9bbbce5e9f2a00abd1bf3dc91e955108700000000", transaction.serialize());
    }

    @Test
    public void serialize3() throws NoSuchAlgorithmException, IOException {
        TransactionInput transactionInput = new TransactionInput(
            "3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac",
            ZERO,
            new Script(new ArrayList<>()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );

        TransactionOutput transactionOutput = new TransactionOutput(valueOf(1_000_000), Script.p2pkhScript(Base58.decodeWithChecksumToHex("1GtpSrGhRGY5kkrNz4RykoqRQoJuG2L6DS")));

        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput);

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, false);

        assertEquals("0100000001aca7f3b45654c230e0886a57fb988c3044ef5e8f7f39726d305c61d5e818903c0000000000ffffffff0140420f00000000001976a914ae56b4db13554d321c402db3961187aed1bbed5b88ac00000000", transaction.serialize());
    }

    @Test
    public void serializeSegwit() throws IOException {
        String txHex = "01000000000101076b57644e155af90f5d9f416b44a3794e0b982c2c427f0845c0e0c62fbb346f0000000000fdffffff0198eb100000000000160014934478b061fa4b5b4dba4f314fb380f3ef77e21902483045022100b7fcf54ae5d7c645b5b44ef7f846e95de9a97a099a447bf8daf14a46f5e3d464022025e709d6794a6fd5b69a7d271fc9a93fcc170b38cfbe5640b6c5d6ec88f021240121025330a1df68c516d32a87ea8ea3da573fa9d86b1b173875beecbf0bdbe45cba8cea7c0a00";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(txHex, transaction.serialize());
    }

    @Test
    public void serializeSegwit2() throws IOException {
        String txHex = "02000000000101a7d259daff3c5ab82bf79b183ca82b1c30d5803ba238f87cde51b4b4b2d3eee10100000000ffffffff02204e000000000000160014b92e162808d34111cbccfb60ff200df058e4ac415911000000000000160014699e2580a45a56c0916aaceab1fcc41c0d30e4080247304402202aff7cb99e8bda7980a814b8347d48e441844f20548047fb3f348fdf0cf0ee4e02206f0e50e3443f8a9364ebef6412c7e6ad8fff895e7cf1a3f0332b8d7d93053b310121026298c137dd1e07f0ba5fc1f74af934fabea5415e9c2632b4cc100abbdf080d4000000000";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(txHex, transaction.serialize());
    }

    @Test
    public void sigHash() throws IOException, NoSuchAlgorithmException {
        String txHex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        String scriptPubkeyHex = "1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        String expectedSighash = "27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6";
        assertEquals(expectedSighash, transaction.sigHash(0, Script.fromByteStream(new ByteArrayInputStream(Hex.decode(scriptPubkeyHex)))));
    }

    @Test
    public void sigHashSegwit() throws IOException, NoSuchAlgorithmException {
        String txHex = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
        String hash160Pubkey = "141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
        BigInteger amount = valueOf(600_000_000);
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        String expectedSighash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
        assertEquals(expectedSighash, transaction.sigHashSegwit(1, Script.p2pkhScript(hash160Pubkey), amount));
    }

    private static Stream<Arguments> testParameters() {
        return Stream.of(
            Arguments.of(
                "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600"
            ),
            Arguments.of(
                "01000000000101076b57644e155af90f5d9f416b44a3794e0b982c2c427f0845c0e0c62fbb346f0000000000fdffffff0198eb100000000000160014934478b061fa4b5b4dba4f314fb380f3ef77e21902483045022100b7fcf54ae5d7c645b5b44ef7f846e95de9a97a099a447bf8daf14a46f5e3d464022025e709d6794a6fd5b69a7d271fc9a93fcc170b38cfbe5640b6c5d6ec88f021240121025330a1df68c516d32a87ea8ea3da573fa9d86b1b173875beecbf0bdbe45cba8cea7c0a00"
            )
        );
    }

}
