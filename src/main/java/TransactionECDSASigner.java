import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class TransactionECDSASigner {
    private static final String HASH_160_PUBKEY_SIZE_HEX = "14";

    public static void sign(Transaction transaction, PrivateKey privateKey, int index, BigInteger amount, boolean isSegwitInput) throws NoSuchAlgorithmException, IOException {
        String sigHash = getSigHash(transaction, privateKey, index, amount, isSegwitInput);
        String derSignature = ECSigner.sign(privateKey, Hex.decode(sigHash)).derHex();
        String signature = derSignature.concat(Hex.toHexString(SigHashTypes.SIGHASH_ALL.toByteArray()));
        if (!isSegwitInput) {
            transaction.getInputs().get(index).setScriptSig(new Script(List.of(signature, privateKey.getPublicKey().compressedPublicKeyHex())));
            return;
        }
        transaction.getInputs().get(index).setWitness(new Witness(List.of(signature, privateKey.getPublicKey().compressedPublicKeyHex())));
    }

    private static String getSigHash(Transaction transaction, PrivateKey privateKey, int index, BigInteger amount, boolean isSegwitInput) throws NoSuchAlgorithmException, IOException {
        if (isSegwitInput) {
            String hash160Pubkey = getHash160Pubkey(privateKey);
            return transaction.sigHashSegwit(index, Script.p2pkhScript(HASH_160_PUBKEY_SIZE_HEX.concat(hash160Pubkey)), amount);
        }
        return transaction.sigHash(index, Script.p2pkhScript(getHash160Pubkey(privateKey)));
    }

    private static String getHash160Pubkey(PrivateKey privateKey) throws NoSuchAlgorithmException {
        return Hash160.hashToHex(privateKey.getPublicKey().getCompressedPublicKey());
    }
}
