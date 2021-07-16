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

        PrivateKey privateKey = PrivateKey.fromWif("cSW3tzg8jNJPUqNyntwJSPXtQW2EcWEwZfsLCK6nHfAEyrJsZ7x7", true);

        System.out.println("private key for p2wpkh input: " + privateKey.getSecret());
        final String address = privateKey.getPublicKey().segwitAddressFromCompressedPublicKey(TESTNET_P2WPKH_ADDRESS_PREFIX);
        System.out.println("address for p2wpkh input: " + address);

        String p2wpkhInputTransactionId = "88807c5e0731a898b7010d29372649a17864eaf9177910e6a535a42cd6c54289";
        TransactionInput transactionInput1 = new TransactionInput(
            p2wpkhInputTransactionId,
            BigInteger.ZERO,
            new Script(List.of()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput1);

        BigInteger amount = BigInteger.valueOf(5_000);
        Script script = Script.p2trScript(Bech32.decode("tb", "tb1psmxksw0jx8eu5ds5yphsszyjagw5ug2ce2z35j0mk8ytkunh3f2sugn56k")[1]);
        TransactionOutput transactionOutput= new TransactionOutput(amount, script);
        System.out.println("output 0 address: " + "tb1psmxksw0jx8eu5ds5yphsszyjagw5ug2ce2z35j0mk8ytkunh3f2sugn56k");
        System.out.println("output 0 amount: " + "5.000 satoshis");

        TransactionOutput transactionOutputChange = new TransactionOutput(BigInteger.valueOf(94_000), Script.p2wpkhScript(Bech32.decode("tb", address)[1]));
        System.out.println("output 1 address: " + address);
        System.out.println("output 1 amount: " + "94.000 satoshis");

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);
        transactionOutputArrayList.add(transactionOutputChange);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, true);
        System.out.println("unsigned transaction: " + transaction.serialize());
        TransactionECDSASigner.sign(transaction, privateKey, 0, BigInteger.valueOf(100_000), true);

        System.out.println("signed transaction: " + transaction.serialize());
        System.out.println("transaction id: " + transaction.id());
    }
}
