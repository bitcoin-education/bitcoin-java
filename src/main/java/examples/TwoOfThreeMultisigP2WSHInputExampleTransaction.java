package examples;

import io.github.bitcoineducation.bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import static io.github.bitcoineducation.bitcoinjava.OpCodes.*;
import static java.math.BigInteger.valueOf;

public class TwoOfThreeMultisigP2WSHInputExampleTransaction {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "b6ba7053c2c7440eaff024b68f4305d5";
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        System.out.println("private key 1 for p2wsh input: " + secret);

        String secret2 = "9fc497a83416458a8296e952b738154d";
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));
        System.out.println("private key 2 for p2wsh input: " + secret2);

        String secret3 = "42980cf8649f435bbc6c37614a366967";
        PrivateKey privateKey3 = new PrivateKey(new BigInteger(1, Hex.decode(secret3)));
        System.out.println("private key 3 for p2wsh input: " + secret3);

        Script redeemScript = new Script(
            List.of(
                valueOf(OP_2),
                privateKey1.getPublicKey().compressedPublicKeyHex(),
                privateKey2.getPublicKey().compressedPublicKeyHex(),
                privateKey3.getPublicKey().compressedPublicKeyHex(),
                valueOf(OP_3),
                valueOf(OP_CHECKMULTISIG)
            )
        );
        String address = redeemScript.p2wshAddress(AddressConstants.TESTNET_P2WPKH_ADDRESS_PREFIX);
        System.out.println("p2wsh address: ".concat(address));

        String p2wskhInputTransactionId = "c0ad7c5f72bc6e5cbca7fc27d47773de9b4be6f996e551b0d5ff98c5ca4262fa";
        TransactionInput transactionInput = new TransactionInput(
            p2wskhInputTransactionId,
            BigInteger.ONE,
            new Script(List.of()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput);

        BigInteger amount = BigInteger.valueOf(9_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2wpkhScript(Bech32.decodeToHex("tb", address)));
        System.out.println("output 0 address: " + address);
        System.out.println("output 0 amount: " + "9,000 satoshis");
        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, true);
        System.out.println("unsigned transaction: " + transaction.serialize());
        P2WSHTransactionECDSASigner.partialSign(transaction, privateKey1, 0, redeemScript, BigInteger.valueOf(10_000));
        P2WSHTransactionECDSASigner.partialSign(transaction, privateKey2, 0, redeemScript, BigInteger.valueOf(10_000));
        P2WSHTransactionECDSASigner.appendRedeemScript(transaction,0, redeemScript);

        System.out.println("signed transaction: " + transaction.serialize());
    }
}
