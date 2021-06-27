package examples;

import bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static bitcoinjava.AddressConstants.*;

public class OneP2WPKHInputExampleTransaction {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "4b357284216a4262a36cc166018b9302";
        System.out.println("private key for p2wpkh input: " + secret);
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        System.out.println("address for p2wpkh input: " + privateKey.getPublicKey().segwitAddressFromCompressedPublicKey(TESTNET_P2WPKH_ADDRESS_PREFIX));

        String p2wpkhInputTransactionId = "5e09f2572117a66154a0f45db6e611e8a46fbb017343b01b4bcc50348f4b8d40";
        TransactionInput transactionInput1 = new TransactionInput(
            p2wpkhInputTransactionId,
            BigInteger.ZERO,
            new Script(List.of()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput1);

        BigInteger amount2 = BigInteger.valueOf(10_000);
        TransactionOutput transactionOutputChange = new TransactionOutput(amount2, Script.p2wpkhScript(Bech32.decode("tb", "tb1q63rv8027mnhszkmf0f5qkxhk48r9tcyk0n6m8l")[1]));
        System.out.println("output 0 address: " + "tb1q63rv8027mnhszkmf0f5qkxhk48r9tcyk0n6m8l");
        System.out.println("output 0 amount: " + "10,000 satoshis");

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutputChange);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, true);
        System.out.println("unsigned transaction: " + transaction.serialize());
        TransactionECDSASigner.sign(transaction, privateKey, 0, BigInteger.valueOf(50_000), true);

        System.out.println("signed transaction: " + transaction.serialize());
    }
}
