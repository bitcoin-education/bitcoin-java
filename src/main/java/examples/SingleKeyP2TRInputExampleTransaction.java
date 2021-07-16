package examples;

import bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static bitcoinjava.AddressConstants.TESTNET_P2WPKH_ADDRESS_PREFIX;

public class SingleKeyP2TRInputExampleTransaction {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "ec88a6704b4f47d5a2e52a1157bb28b9";
        System.out.println("private key for p2tr input: " + secret);
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        PublicKey internalKey = privateKey.getPublicKey().toTaprootInternalKey();
        PublicKey outputKey = internalKey.toTaprootSingleKeyOutputKey();
        PrivateKey secretKey = privateKey.toTaprootTweakSeckey(BigInteger.ZERO);

        String address = outputKey.taprootAddress(TESTNET_P2WPKH_ADDRESS_PREFIX);
        System.out.println("address for p2tr input: " + address);

        String p2wpkhInputTransactionId = "37f67076d3da37ed0997056f8dde7a971248a68373b67e48095eda5457b77657";
        TransactionInput transactionInput1 = new TransactionInput(
            p2wpkhInputTransactionId,
            BigInteger.ZERO,
            new Script(new ArrayList<>()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput1);

        BigInteger amount = BigInteger.valueOf(4_000);
        Script script = Script.p2trScript(Bech32.decode("tb", "tb1psmxksw0jx8eu5ds5yphsszyjagw5ug2ce2z35j0mk8ytkunh3f2sugn56k")[1]);
        TransactionOutput transactionOutput = new TransactionOutput(amount, script);
        System.out.println("output 0 address: " + "tb1psmxksw0jx8eu5ds5yphsszyjagw5ug2ce2z35j0mk8ytkunh3f2sugn56k");
        System.out.println("output 0 amount: " + "4,000 satoshis");
        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, true);
        System.out.println("unsigned transaction: " + transaction.serialize());
        TransactionSchnorrSigner.sign(transaction, secretKey.getSecret(), 0, List.of(BigInteger.valueOf(5_000)), List.of(script));

        System.out.println("signed transaction: " + transaction.serialize());
        System.out.println("transaction id: " + transaction.id());
    }
}
