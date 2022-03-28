import io.github.bitcoineducation.bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.stream.Stream;

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
    public void serialize2() throws IOException {
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
    public void serialize3() throws IOException {
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
    public void sigHash() throws IOException {
        String txHex = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        String scriptPubkeyHex = "1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        String expectedSighash = "27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6";
        assertEquals(expectedSighash, transaction.sigHash(0, Script.fromByteStream(new ByteArrayInputStream(Hex.decode(scriptPubkeyHex)))));
    }

    @Test
    public void sigHashNestedSegwit() throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String txHex = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")));
        Script redeemScript = Script.p2wpkhScript(Hash160.hashToHex(privateKey.getPublicKey().getCompressedPublicKey()));
        String sigHash = transaction.sigHashSegwit(0, Script.p2pkhScript("14".concat((String) redeemScript.getCommands().get(1))).serializeForSegwitSigHash(), valueOf(1_000_000_000L));
        String expectedSigHash = "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6";
        assertEquals(expectedSigHash, sigHash);
    }

    @Test
    public void sigHashSegwit() throws IOException {
        String txHex = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
        String hash160Pubkey = "141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
        BigInteger amount = valueOf(600_000_000);
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        String expectedSighash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670";
        assertEquals(expectedSighash, transaction.sigHashSegwit(1, Script.p2pkhScript(hash160Pubkey).serializeForSegwitSigHash(), amount));
    }

    @ParameterizedTest
    @MethodSource("testVSizeParameters")
    public void testVSize(String txHex, int lengthWithoutWitness) throws IOException {
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        int lengthWithWitness = Hex.decode(transaction.serialize()).length;
        int witnessLength = lengthWithWitness - lengthWithoutWitness;
        int weight = witnessLength + lengthWithoutWitness * 4;
        int vSize = (weight + 3) / 4;
        assertEquals(vSize, transaction.getVSize());
    }

    @ParameterizedTest
    @MethodSource("testVSizeParameters2")
    public void testVSize2(String txHex, int expectedVSize) throws IOException {
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        assertEquals(expectedVSize, transaction.getVSize());
    }

    public static Stream<Arguments> testVSizeParameters() {
        return Stream.of(
            Arguments.of(
                "010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000",
                60
            ),
            Arguments.of(
                "0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000008b483045022100da43201760bda697222002f56266bf65023fef2094519e13077f777baed553b102205ce35d05eabda58cd50a67977a65706347cc25ef43153e309ff210a134722e9e0141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac00000000",
                224
            ),
            Arguments.of(
                "020000000001012f94ddd965758445be2dfac132c5e75c517edf5ea04b745a953d0bc04c32829901000000006aedc98002a8c500000000000022002009246bbe3beb48cf1f6f2954f90d648eb04d68570b797e104fead9e6c3c87fd40544020000000000160014c221cdfc1b867d82f19d761d4e09f3b6216d8a8304004830450221008aaa56e4f0efa1f7b7ed690944ac1b59f046a59306fcd1d09924936bd500046d02202b22e13a2ad7e16a0390d726c56dfc9f07647f7abcfac651e35e5dc9d830fc8a01483045022100e096ad0acdc9e8261d1cdad973f7f234ee84a6ee68e0b89ff0c1370896e63fe102202ec36d7554d1feac8bc297279f89830da98953664b73d38767e81ee0763b9988014752210390134e68561872313ba59e56700732483f4a43c2de24559cb8c7039f25f7faf821039eb59b267a78f1020f27a83dc5e3b1e4157e4a517774040a196e9f43f08ad17d52ae89a3b720",
                125
            )
        );
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

    public static Stream<Arguments> testVSizeParameters2() {
        return Stream.of(
            Arguments.of(
                "020000000001056723b6cf393c9d86adf30d351ac706891c9ef652a4153ce96ef2099df61f98c11d00000017160014f0e56465acdb81ff336b3bbb87350a2012228576feffffffac0be5325c53565717b56e8a11eaba5b977d145f39619edec2cb8f19af166a570d000000171600143ad752a0bbec46b37c28e746b2569bea7516fb53feffffffa4023a13d7856d5ccf986eddd7e1a77ff980a2b1d3f86625ffc3caee701cea6a0b00000017160014ab92030f40796efad21655c0a66a71a888923c7dfeffffffdd3da61fdb434a5a5908cd9cb6f205681396efa978569afc5a75e50fa58933f1000000001716001484fe48e0295b9fa4b4fe1a515d95c2ec475507abfeffffffa4023a13d7856d5ccf986eddd7e1a77ff980a2b1d3f86625ffc3caee701cea6a0e00000017160014c93bbc4de22ac49d898df66deaed58a767b54845feffffff01c08406000000000017a9142fcecb72802a509d8e96dff6baa305cdf9ac667b87024730440220586a434b8318262472d8513c84481d7d08b97fbabf800f6aa14d5a76e307572502201d553d16d45e2802146546707f55217aee87b29a3107af514a3819b6af6a8c7501210360f329756513c76a497660721218b5cde82d18cc50c2730e77a808e8a9c19f1102473044022075cf3b4265c189ec6aef2fe7c2973879510ab09d75e9a99cd3589511803434b602207d7616938b5e65a5838058b9ace2f586a27dd3ce5901dd39d083fec8a0aa891b012102d937fa0c98cc8cec64681677d447f87fcb9c01e27dad59486f6e40ce00ad41f402473044022040b60e1050429e7c51a3fdc4033835d84897c5532c63a422b020e0d567cee21202202c10d3bcbd1558cc8e5d7851d7832b7e32567669f97d4835745c639450cffeb101210313657a6d64563ce03f5d9d4bbe29abc3a15b80ea8ab7b2006e18c79dd4aaa96b02473044022074daee0a01f5b01382c09117773a96c4d3a06d847f11805b3e95bc6ae774181b022041bd7daca93a2efafe46a31e892ee408e27567dcab22081f9ba07b99a9d771e401210208d4273caaac6c9d263fffbd61d52080951376ff4778fbfe2988f6940194a608024730440220403d952ee314ce96fa1b7af289c0933b10772fbf9ad8aed5448f15b4a6c7576502202f5921b32797fb5f57c3db55ef1ecb04cae0137bfc0199d77f90b27c26c20322012103c3e79ed7448ac33c0234f0812db0acbdefe3670e5a41e32a225ebc2f6b63dfc7ee200b00",
                497
            ),
            Arguments.of(
                "020000000001043025c5159bbe2cbdae741d31e551eb48c5c1078133a51a1d7a046ebf23ae194c3e00000000ffffffffcfac880c144c02e2646a38b2e3db69ead21c2cd9891f227c4d9bb03097f4a5fe1e00000000ffffffff8cd8d6da39e6790b793312c016f8da863ea570056687826ae84b6ea252810df92400000000ffffffffb1b463c86bbee268f654d1c177dd6ec18bf6e7c7127767c6995af4735a915d390a00000000ffffffff02401640000000000016001454e0c2d7d8dc2fccd4c688b63d35f43e283f86ad1278010000000000160014e9f01945feaf8ffbd8bfdad35dfc545b5dca907002483045022100dda80bc76b6c4725f3ee80479bd10d6df54f57124b82aa8b4e2f6a1c8e669b160220536eeeb4fcbdca34d6e55bbe951e79a2522a2bb1c38d7604a9312760539eb10a01210278027fae992d5baa8b45e5427b58cdecb2cd4ccad2d0807d215962a2fd66049d02473044022009c88fb671b8f15fb02b94039d00e08d1c1e457ca238fc9406c11fd4878f742a02204e6c31c88cf4209631fd2e3d3e7adfef5e3ddc34d8cd98dc0ad40fbfc94a150901210278027fae992d5baa8b45e5427b58cdecb2cd4ccad2d0807d215962a2fd66049d024730440220174ead317a44acbdbb8d0ca083d01e38ad92f982bd8b082f105662a2d534cdc8022049fac331335d2930505a51d72532ab0a10142ea51326713e1de57c145fb3b63c01210278027fae992d5baa8b45e5427b58cdecb2cd4ccad2d0807d215962a2fd66049d02483045022100c4a2ac0432aa8e2b3d0e92b821f2395f230cf51a6a5b90c91b0875cdd7450715022075994ced792f37f94d6bde069fa0256118c290703d0052a191bb76073096231c01210278027fae992d5baa8b45e5427b58cdecb2cd4ccad2d0807d215962a2fd66049d00000000",
                344
            ),
            Arguments.of(
                "01000000010d792496b9cc255c5e6204cee07de3d340c6b990f85e59ade10795e2b224402c010000006b483045022100ccabec224012c74d67b765ff4a7e19500ab61c6b6ef8d3bb23c76af6915a72850220257194c42a119698984db2610cdda8181f69de6c929ede45ccbfca6b4d08d61c01210221e0678b32f14a4ff949382090bedcaf39929e6a2bee1eadecf2164d32a0819fffffffff01905f010000000000160014d446c3bd5edcef015b697a680b1af6a9c655e09600000000",
                189
            )
        );
    }

}
