package bitcoinjava;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.stream.Collectors;

public class TransactionSchnorrSigner {
    public static void sign(Transaction transaction, BigInteger secret, int index, List<BigInteger> amounts, List<Script> scripts) throws IOException {
        String sigHash = getSigHash(transaction, index, amounts, scripts);
        byte[] message = ByteUtils.concatenate(new byte[]{0}, Hex.decodeStrict(sigHash));
        byte[] taggedMessage = TaggedHash.hash("TapSighash", message);

        byte[] auxRand = getAuxRand();
        BigInteger signature = SchnorrSigner.sign(secret, new BigInteger(1, taggedMessage), new BigInteger(1, auxRand));
        String signatureHex = Hex.toHexString(BigIntegers.asUnsignedByteArray(signature));

        transaction.getInputs().get(index).setWitness(new Witness(List.of(signatureHex)));
    }

    private static byte[] getAuxRand() {
        byte[] auxRand = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(auxRand);
        return auxRand;
    }

    private static String getSigHash(Transaction transaction, int index, List<BigInteger> amounts, List<Script> scripts) throws IOException {
        List<String> scriptsSerialized = scripts.stream().map(script -> {
            try {
                return script.serialize();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }).collect(Collectors.toList());
        return transaction.sigHashTaproot(
            index,
            scriptsSerialized,
            amounts
        );
    }
}
