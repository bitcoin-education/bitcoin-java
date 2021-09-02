package examples;

import io.github.bitcoineducation.bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;

public class OneNestedSegwitInputExampleTransaction {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        String secret = "dee42df9945848a98209557e7222d018";
        System.out.println("private key for p2sh-p2wpkh input: " + secret);
        PrivateKey privateKey = new PrivateKey(new BigInteger(1, Hex.decode(secret)));
        String address = Script.p2wpkhScript(Hash160.hashToHex(privateKey.getPublicKey().getCompressedPublicKey())).p2shAddress(AddressConstants.TESTNET_P2SH_ADDRESS_PREFIX);
        System.out.println("address for p2sh-p2wpkh: " + address);

        Script redeemScript = Script.p2wpkhScript(Hash160.hashToHex(privateKey.getPublicKey().getCompressedPublicKey()));

        String txid = "909eb6e2c3b468bf5bdbd68a0bec4cf5e1c3a814f41467607fc49c279b71dba4";
        TransactionInput transactionInput0 = new TransactionInput(
            txid,
            BigInteger.ZERO,
            new Script(new ArrayList<>()),
            new BigInteger(1, Hex.decode("ffffffff"))
        );

        ArrayList<TransactionInput> transactionInputArrayList = new ArrayList<>();
        transactionInputArrayList.add(transactionInput0);

        BigInteger amount = BigInteger.valueOf(98_000);
        TransactionOutput transactionOutput = new TransactionOutput(amount, Script.p2shScript(Base58.decodeWithChecksumToHex(address)));
        System.out.println("output 0 address: " + address);
        System.out.println("output 0 amount: " + "98,000 satoshis");

        ArrayList<TransactionOutput> transactionOutputArrayList = new ArrayList<>();
        transactionOutputArrayList.add(transactionOutput);

        Transaction transaction = new Transaction(BigInteger.ONE, transactionInputArrayList, transactionOutputArrayList, BigInteger.ZERO, true);
        System.out.println("unsigned transaction: " + transaction.serialize());

        P2SHTransactionECDSASigner.signNestedSegwit(transaction, privateKey, 0, redeemScript, BigInteger.valueOf(100_000));

        System.out.println("signed transaction: " + transaction.serialize());
    }
}
