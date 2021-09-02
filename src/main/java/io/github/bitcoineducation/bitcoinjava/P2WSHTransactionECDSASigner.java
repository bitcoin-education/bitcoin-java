package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;

public class P2WSHTransactionECDSASigner {
    public static void partialSign(Transaction transaction, PrivateKey privateKey, int index, Script redeemScript, BigInteger amount) throws IOException {
        String sigHash = getSigHash(transaction, index, redeemScript, amount);
        String derSignature = ECSigner.sign(privateKey, Hex.decode(sigHash)).derHex();
        String signature = derSignature.concat(Hex.toHexString(SigHashTypes.SIGHASH_ALL.toByteArray()));
        transaction.getInputs().get(index).appendToWitness(signature);
    }

    public static void appendRedeemScript(Transaction transaction, int index, Script redeemScript) {
        transaction.getInputs().get(index).appendToWitness(redeemScript.rawSerialize());
    }

    private static String getSigHash(Transaction transaction, int index, Script redeemScript, BigInteger amount) throws IOException {
        return transaction.sigHashSegwit(index, redeemScript.serialize(), amount);
    }
}
