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

public class OneOfTwoMultisigNestedSegwitInputExampleTransaction {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "d6250b7db8ac4df49c5c9a0ba1e693dc";
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        System.out.println("private key 1 for p2wsh input: " + secret);

        String secret2 = "31a1c62386d14190917197edd2d19f0d";
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));
        System.out.println("private key 2 for p2wsh input: " + secret2);

        Script redeemScript = new Script(List.of(valueOf(OP_1), privateKey1.getPublicKey().compressedPublicKeyHex(), privateKey2.getPublicKey().compressedPublicKeyHex(), valueOf(OP_2), valueOf(OP_CHECKMULTISIG)));

        Script scriptPubkey = Script.p2wpkhScript(Sha256.hashToHex(redeemScript.rawSerialize()));
        String address = scriptPubkey.p2shAddress(AddressConstants.TESTNET_P2SH_ADDRESS_PREFIX);
        System.out.println("p2sh address: " + address);

        String p2wpkhInputTransactionId = "58726f0cc61734c6f6852dd20d825fc69678d7ff2b3bd932f65178cfa365c659";
        TransactionInput transactionInput = new TransactionInput(
            p2wpkhInputTransactionId,
            BigInteger.ZERO,
            new Script(new ArrayList<>()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );
        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput);

        BigInteger amount = BigInteger.valueOf(99_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2shScript(Base58.decodeWithChecksumToHex(address)));
        System.out.println("output 0 address: " + address);
        System.out.println("output 0 amount: " + "99,000 satoshis");

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, true);
        System.out.println("unsigned transaction: " + transaction.serialize());

        P2WSHTransactionECDSASigner.partialSign(transaction, privateKey1, 0, redeemScript, BigInteger.valueOf(100_000));
        P2WSHTransactionECDSASigner.appendRedeemScript(transaction, 0, redeemScript);
        P2SHTransactionECDSASigner.appendRedeemScript(transaction, 0, scriptPubkey);

        System.out.println("signed transaction: " + transaction.serialize());
    }
}
