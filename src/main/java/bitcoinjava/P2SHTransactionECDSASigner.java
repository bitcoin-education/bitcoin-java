package bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class P2SHTransactionECDSASigner {

    public static void partialSign(Transaction transaction, PrivateKey privateKey, int index, Script redeemScript) throws NoSuchAlgorithmException, IOException {
        String sigHash = getSigHash(transaction, index, redeemScript);
        String derSignature = ECSigner.sign(privateKey, Hex.decode(sigHash)).derHex();
        String signature = derSignature.concat(Hex.toHexString(SigHashTypes.SIGHASH_ALL.toByteArray()));
        transaction.getInputs().get(index).appendToP2SHScriptSig(signature);
    }

    public static void appendRedeemScript(Transaction transaction, int index, Script redeemScript) {
        transaction.getInputs().get(index).getScriptSig().appendCommand(redeemScript.rawSerialize());
    }

    private static String getSigHash(Transaction transaction, int index, Script redeemScript) throws NoSuchAlgorithmException {
        return transaction.sigHash(index, redeemScript);
    }
}
