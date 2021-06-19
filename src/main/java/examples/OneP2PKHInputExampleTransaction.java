package examples;

import bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class OneP2PKHInputExampleTransaction {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "f2148bbebe0c4f2ba91265f323fef7e2";
        System.out.println("private key for p2pkh input: " + secret);
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        System.out.println("address for p2pkh input: " + privateKey.getPublicKey().addressFromCompressedPublicKey(AddressConstants.TESTNET_P2PKH_ADDRESS_PREFIX));

        String id = "2c4024b2e29507e1ad595ef890b9c640d3e37de0ce04625e5c25ccb99624790d";
        TransactionInput transactionInput = new TransactionInput(
            id,
            BigInteger.ONE,
            new Script(List.of()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput);

        BigInteger amount = BigInteger.valueOf(90_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2wpkhScript(Bech32.decode("tb", "tb1q63rv8027mnhszkmf0f5qkxhk48r9tcyk0n6m8l")[1]));
        System.out.println("output 0 address: " + "tb1q63rv8027mnhszkmf0f5qkxhk48r9tcyk0n6m8l");
        System.out.println("output 0 amount: " + "90,000 satoshis");

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, false);
        System.out.println("unsigned transaction: " + transaction.serialize());
        TransactionECDSASigner.sign(transaction, privateKey, 0, null, false);

        System.out.println("signed transaction: " + transaction.serialize());
    }
}
