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

public class MixedInputsP2PKH_P2WPKHExampleTransaction {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "f2148bbebe0c4f2ba91265f323fef7e2";
        System.out.println("private key for p2pkh input: " + secret);
        PrivateKey privateKey1 = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        System.out.println("address for p2pkh input: " + privateKey1.getPublicKey().addressFromCompressedPublicKey(AddressConstants.TESTNET_P2PKH_ADDRESS_PREFIX));

        String secret2 = "4b357284216a4262a36cc166018b9302";
        System.out.println("private key for p2wpkh input: " + secret2);
        PrivateKey privateKey2 = new PrivateKey(new BigInteger(1, Hex.decode(secret2)));
        System.out.println("address for p2wpkh input: " + privateKey2.getPublicKey().segwitAddressFromCompressedPublicKey(TESTNET_P2WPKH_ADDRESS_PREFIX));

        String secret3 = "b2765554df17437f99110559747ce62f";
        System.out.println("private key for p2wpkh input: " + secret3);
        PrivateKey privateKey3 = new PrivateKey(new BigInteger(1, Hex.decode(secret3)));
        System.out.println("address for p2wpkh output: " + privateKey3.getPublicKey().segwitAddressFromCompressedPublicKey(TESTNET_P2WPKH_ADDRESS_PREFIX));

        String p2pkhInputTransactionId = "d85fc5ef33bfe87836e5ce88cd0943a7c0a6d19b2753ab655c2f95da57732b14";
        TransactionInput transactionInput0 = new TransactionInput(
            p2pkhInputTransactionId,
            BigInteger.ONE,
            new Script(List.of()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );

        String p2wpkhInputTransactionId = "d85fc5ef33bfe87836e5ce88cd0943a7c0a6d19b2753ab655c2f95da57732b14";
        TransactionInput transactionInput1 = new TransactionInput(
            p2wpkhInputTransactionId,
            BigInteger.ZERO,
            new Script(List.of()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );

        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput0);
        transactionInputArrayList.add(transactionInput1);

        BigInteger amount = BigInteger.valueOf(70_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2wpkhScript(Bech32.decode("tb", "tb1qwe4smkkxcz84m82xvq78k6y9n8jl8kddxjjg35")[1]));
        System.out.println("output 0 address: " + "tb1qwe4smkkxcz84m82xvq78k6y9n8jl8kddxjjg35");
        System.out.println("output 0 amount: " + "70,000 satoshis");

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, true);
        System.out.println("unsigned transaction: " + transaction.serialize());

        TransactionECDSASigner.sign(transaction, privateKey1, 0, null, false);
        TransactionECDSASigner.sign(transaction, privateKey2, 1, BigInteger.valueOf(40_000), true);

        System.out.println("signed transaction: " + transaction.serialize());
    }
}
