package examples;

import bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static bitcoinjava.OpCodes.*;
import static java.math.BigInteger.valueOf;

public class TwoOfTwoMultisigP2SHInputExampleTransaction {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "f06812134dcf4ce5bb0dabd7718b1528";
        System.out.println("private key 1 for p2sh input: " + secret);
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));

        String secret2 = "ad7abc3d183d499392cc43a12561c924";
        System.out.println("private key 2 for p2sh input: " + secret2);
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));

        Script redeemScript = new Script(List.of(
            valueOf(OP_2),
            privateKey1.getPublicKey().compressedPublicKeyHex(),
            privateKey2.getPublicKey().compressedPublicKeyHex(),
            valueOf(OP_2), valueOf(OP_CHECKMULTISIG)
        ));
        System.out.println("p2sh address: " + redeemScript.p2shAddress(AddressConstants.TESTNET_P2SH_ADDRESS_PREFIX));

        String p2shInputTransactionId = "093b24dc0df9230a0e2a31471f2fafbb72943770bef62c09c5175e8b2396fae3";
        TransactionInput transactionInput0 = new TransactionInput(
            p2shInputTransactionId,
            BigInteger.ZERO,
            new Script(new ArrayList<>()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );

        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput0);

        BigInteger amount = BigInteger.valueOf(48_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2wpkhScript(Bech32.decode("tb", "tb1q63rv8027mnhszkmf0f5qkxhk48r9tcyk0n6m8l")[1]));
        System.out.println("output 0 address: " + "tb1q63rv8027mnhszkmf0f5qkxhk48r9tcyk0n6m8l");
        System.out.println("output 0 amount: " + "48,000 satoshis");

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, false);
        System.out.println("unsigned transaction: " + transaction.serialize());

        P2SHTransactionECDSASigner.partialSign(transaction, privateKey1, 0, redeemScript);
        P2SHTransactionECDSASigner.partialSign(transaction, privateKey2, 0, redeemScript);
        P2SHTransactionECDSASigner.appendRedeemScript(transaction,  0, redeemScript);

        System.out.println("signed transaction: " + transaction.serialize());
    }
}
