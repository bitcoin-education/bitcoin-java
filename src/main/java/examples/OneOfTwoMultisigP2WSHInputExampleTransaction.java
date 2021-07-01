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

public class OneOfTwoMultisigP2WSHInputExampleTransaction {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "75a0c09158b643779a11e3e2c512e1c1";
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        System.out.println("private key 1 for p2wsh input: " + secret);

        String secret2 = "b590963c9f1543c88207509e4e98a086";
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));
        System.out.println("private key 2 for p2wsh input: " + secret2);

        Script redeemScript = new Script(List.of(valueOf(OP_1), privateKey1.getPublicKey().compressedPublicKeyHex(), privateKey2.getPublicKey().compressedPublicKeyHex(), valueOf(OP_2), valueOf(OP_CHECKMULTISIG)));
        String address = redeemScript.p2wshAddress(AddressConstants.TESTNET_P2WPKH_ADDRESS_PREFIX);
        System.out.println("p2wsh address: ".concat(address));

        String p2wskhInputTransactionId = "8471ae939ceb57c89d1d02ac9717bdc33650d0df15cf9694a5037b3079733319";
        TransactionInput transactionInput = new TransactionInput(
            p2wskhInputTransactionId,
            BigInteger.ONE,
            new Script(List.of()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput);

        BigInteger amount = BigInteger.valueOf(98_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2wpkhScript(Bech32.decode("tb", address)[1]));
        System.out.println("output 0 address: " + address);
        System.out.println("output 0 amount: " + "98,000 satoshis");
        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, true);
        System.out.println("unsigned transaction: " + transaction.serialize());
        P2WSHTransactionECDSASigner.partialSign(transaction, privateKey1, 0, redeemScript, BigInteger.valueOf(100_000));
        P2WSHTransactionECDSASigner.appendRedeemScript(transaction,0, redeemScript);

        System.out.println("signed transaction: " + transaction.serialize());
    }
}
