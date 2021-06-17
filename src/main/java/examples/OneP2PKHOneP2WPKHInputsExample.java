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
import java.util.UUID;

public class OneP2PKHOneP2WPKHInputsExample {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        String random = UUID.randomUUID().toString().replace("-", "");
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode(random)));

        String random2 = UUID.randomUUID().toString().replace("-", "");
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(random)));
//        System.out.println("Address P2WPKH: ".concat(privateKey2));

        String id = Bytes.reverseFromHex("95f0516a64367f4c2cc66e742bb14f45b82052a0424f26b11fbeef333ba835ce");
        TransactionInput transactionInput = new TransactionInput(
            id,
            BigInteger.ONE,
            new Script(List.of()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput);

        BigInteger amount = BigInteger.valueOf(60_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2pkhScript(Base58.decodeWithChecksumToHex("mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB")));
        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, false);
        TransactionECDSASigner.sign(transaction, privateKey, 0, null, false);
    }
}
