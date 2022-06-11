package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;

public class P2SHTransactionECDSASigner {
    private static final String HASH_160_PUBKEY_SIZE_HEX = "14";

    public static void partialSign(Transaction transaction, PrivateKey privateKey, int index, Script redeemScript) throws IOException {
        String sigHash = getSigHash(transaction, index, redeemScript, null, false);
        String derSignature = ECSigner.sign(privateKey, Hex.decode(sigHash)).derHex();
        String signature = derSignature.concat(Hex.toHexString(SigHashTypes.SIGHASH_ALL.toByteArray()));
        transaction.getInputs().get(index).appendToP2SHScriptSig(signature);
    }

    public static void signNestedSegwit(Transaction transaction, PrivateKey privateKey, int index, Script redeemScript, BigInteger amount) throws IOException {
        String sigHash = getSigHash(transaction, index, redeemScript, amount, true);
        String derSignature = ECSigner.sign(privateKey, Hex.decode(sigHash)).derHex();
        String signature = derSignature.concat(Hex.toHexString(SigHashTypes.SIGHASH_ALL.toByteArray()));
        transaction.getInputs().get(index).setWitness(new Witness(List.of(signature, privateKey.getPublicKey().compressedPublicKeyHex())));
        transaction.getInputs().get(index).setScriptSig(new Script(List.of(redeemScript.rawSerialize())));
    }

    public static void appendRedeemScript(Transaction transaction, int index, Script redeemScript) {
        transaction.getInputs().get(index).getScriptSig().appendCommand(redeemScript.rawSerialize());
    }

    private static String getSigHash(Transaction transaction, int index, Script redeemScript, BigInteger amount, boolean isSegwitInput) throws IOException {
        if (isSegwitInput) {
            return transaction.sigHashSegwit(index, Script.p2pkhScript(HASH_160_PUBKEY_SIZE_HEX.concat((String) redeemScript.getCommands().get(1))).serializeForSegwitSigHash(), amount);
        }
        return transaction.sigHash(index, redeemScript);
    }
}
