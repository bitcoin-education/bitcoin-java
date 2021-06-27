import bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static bitcoinjava.OpCodes.*;
import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class P2SHTransactionECDSASignerTest {
    @Test
    public void sign() throws IOException {
        String secret = "909f2d6fc6564407b73743b6871b70d9";
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));

        String secret2 = "3ab974f2e02e4275beb4e2440794d1ec";
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));

        Script redeemScript = new Script(List.of(
            valueOf(OP_1),
            privateKey1.getPublicKey().compressedPublicKeyHex(),
            privateKey2.getPublicKey().compressedPublicKeyHex(),
            valueOf(OP_2),
            valueOf(OP_CHECKMULTISIG)
        ));

        String p2shInputTransactionId = "0f0e64bc96a42058e7fc0c172de37f12bdae1c276c16647a316adcf39248b850";

        TransactionInput transactionInput0 = new TransactionInput(
            p2shInputTransactionId,
            BigInteger.ZERO,
            new Script(new ArrayList<>()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );

        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput0);

        BigInteger amount = BigInteger.valueOf(55_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2wpkhScript(Bech32.decode("tb", "tb1q63rv8027mnhszkmf0f5qkxhk48r9tcyk0n6m8l")[1]));

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, false);
        P2SHTransactionECDSASigner.partialSign(transaction, privateKey1, 0, redeemScript);
        P2SHTransactionECDSASigner.appendRedeemScript(transaction,  0, redeemScript);

        String expectedTransactionSigned = "010000000150b84892f3dc6a317a64166c271caebd127fe32d170cfce75820a496bc640e0f000000009200483045022100a3b4c518ecdb0efd35bad65bb996c8840af7e503591e82acfc43c532c0fa2ccb02201f40a76927313f3b5d15404929631074cd95c5d2e1885a65604864658b649f6701475121032fb2f3c4acd2e02679d5c0e0222755da7651581b021aa338a34746b7315a2ead2102e589e0d78882525b40186bed65b3c8285e649bbb05321c4e8e2deae0adf085ce52aeffffffff01d8d6000000000000160014d446c3bd5edcef015b697a680b1af6a9c655e09600000000";

        assertEquals(
            expectedTransactionSigned,
            transaction.serialize()
        );

    }

    @Test
    public void signNestedSegwit() throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String txHex = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000";
        Transaction transaction = Transaction.fromByteStream(new ByteArrayInputStream(Hex.decode(txHex)));
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")));
        Script redeemScript = Script.p2wpkhScript(Hash160.hashToHex(privateKey.getPublicKey().getCompressedPublicKey()));

        String expectedTransaction = "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000";
        P2SHTransactionECDSASigner.signNestedSegwit(transaction, privateKey, 0, redeemScript, valueOf(1_000_000_000L));
        transaction.setSegwit(true);
        assertEquals(expectedTransaction, transaction.serialize());
    }

    @Test
    public void testFromParsedTransaction() throws IOException {
        String txHex = "0100000001e3fa96238b5e17c5092cf6be70379472bbaf2f1f47312a0e0a23f90ddc243b090000000000ffffffff0180bb000000000000160014d446c3bd5edcef015b697a680b1af6a9c655e09600000000";
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Hex.decode(txHex));
        Transaction transaction = Transaction.fromByteStream(byteArrayInputStream);

        String secret = "f06812134dcf4ce5bb0dabd7718b1528";
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        String secret2 = "ad7abc3d183d499392cc43a12561c924";
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));

        Script redeemScript = new Script(List.of(
            valueOf(OP_2),
            privateKey1.getPublicKey().compressedPublicKeyHex(),
            privateKey2.getPublicKey().compressedPublicKeyHex(),
            valueOf(OP_2), valueOf(OP_CHECKMULTISIG)
        ));

        P2SHTransactionECDSASigner.partialSign(transaction, privateKey1, 0, redeemScript);
        P2SHTransactionECDSASigner.partialSign(transaction, privateKey2, 0, redeemScript);
        P2SHTransactionECDSASigner.appendRedeemScript(transaction,  0, redeemScript);

        String expectedSignedTransaction = "0100000001e3fa96238b5e17c5092cf6be70379472bbaf2f1f47312a0e0a23f90ddc243b0900000000da00473044022007de61705591da6a052eb0f8d81c6aaa7f6f9e3221f02888385a97dddfec54a702201890610422899a7256bd152ed3587c1905ba84bd3e91a9babd31be2d311fb9d001483045022100bec53fff656f7a7f5c37c88cb520d3bfd20ad9ec91b39a11bbee820dbda2fa1302205a31a2599fadeb456f08990373364e7bf18be303ad36a42a7b4c3df6f19e3bcd0147522103180f6fd4ef4f0af7031d26112c58cd5d9afb6ced783c51dc10f4ec5ef16345322102f80764440872c6d3e7cd81e41082ac53d2c8e4beb5b6dc8f98584024f75eb8f552aeffffffff0180bb000000000000160014d446c3bd5edcef015b697a680b1af6a9c655e09600000000";
        assertEquals(expectedSignedTransaction, transaction.serialize());
    }

    @Test
    public void testFromParsedPartiallySignedTransaction() throws IOException {
        String txHex = "0100000001e3fa96238b5e17c5092cf6be70379472bbaf2f1f47312a0e0a23f90ddc243b09000000004900473044022007de61705591da6a052eb0f8d81c6aaa7f6f9e3221f02888385a97dddfec54a702201890610422899a7256bd152ed3587c1905ba84bd3e91a9babd31be2d311fb9d001ffffffff0180bb000000000000160014d446c3bd5edcef015b697a680b1af6a9c655e09600000000";
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Hex.decode(txHex));
        Transaction transaction = Transaction.fromByteStream(byteArrayInputStream);

        String secret = "f06812134dcf4ce5bb0dabd7718b1528";
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        String secret2 = "ad7abc3d183d499392cc43a12561c924";
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));

        Script redeemScript = new Script(List.of(
            valueOf(OP_2),
            privateKey1.getPublicKey().compressedPublicKeyHex(),
            privateKey2.getPublicKey().compressedPublicKeyHex(),
            valueOf(OP_2), valueOf(OP_CHECKMULTISIG)
        ));

        P2SHTransactionECDSASigner.partialSign(transaction, privateKey2, 0, redeemScript);
        P2SHTransactionECDSASigner.appendRedeemScript(transaction,  0, redeemScript);

        String expectedSignedTransaction = "0100000001e3fa96238b5e17c5092cf6be70379472bbaf2f1f47312a0e0a23f90ddc243b0900000000da00473044022007de61705591da6a052eb0f8d81c6aaa7f6f9e3221f02888385a97dddfec54a702201890610422899a7256bd152ed3587c1905ba84bd3e91a9babd31be2d311fb9d001483045022100bec53fff656f7a7f5c37c88cb520d3bfd20ad9ec91b39a11bbee820dbda2fa1302205a31a2599fadeb456f08990373364e7bf18be303ad36a42a7b4c3df6f19e3bcd0147522103180f6fd4ef4f0af7031d26112c58cd5d9afb6ced783c51dc10f4ec5ef16345322102f80764440872c6d3e7cd81e41082ac53d2c8e4beb5b6dc8f98584024f75eb8f552aeffffffff0180bb000000000000160014d446c3bd5edcef015b697a680b1af6a9c655e09600000000";
        assertEquals(expectedSignedTransaction, transaction.serialize());
    }
}
