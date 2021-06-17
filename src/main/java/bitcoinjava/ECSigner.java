package bitcoinjava;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

import java.math.BigInteger;

public class ECSigner {
    public static Signature sign(PrivateKey privateKey, byte[] message) {
        ECDSASigner ecdsaSigner = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ecdsaSigner.init(
            true,
            new ECPrivateKeyParameters(
                privateKey.getSecret(),
                SecP256K1Constants.ecDomainParameters
            )
        );
        BigInteger[] signature = ecdsaSigner.generateSignature(message);
        if (signature[1].compareTo(SecP256K1Constants.order.divide(BigInteger.TWO)) > 0) {
            signature[1] = SecP256K1Constants.order.subtract(signature[1]);
        }
        return new Signature(signature[0], signature[1]);
    }
}
