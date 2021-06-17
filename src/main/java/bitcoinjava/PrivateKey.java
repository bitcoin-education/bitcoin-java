package bitcoinjava;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class PrivateKey {
    private final BigInteger secret;

    private final PublicKey publicKey;

    public PrivateKey(BigInteger secret) {
        this.secret = secret;
        this.publicKey = new PublicKey(SecP256K1Constants.G.multiply(secret).normalize());
    }

    public BigInteger getSecret() {
        return secret;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String wif(String prefix, boolean compressed) throws NoSuchAlgorithmException {
        byte[] secretBytes = BigIntegers.asUnsignedByteArray(32, secret);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decodeStrict(prefix));
        byteArrayOutputStream.writeBytes(secretBytes);
        if (compressed) {
            byteArrayOutputStream.writeBytes(Hex.decodeStrict("01"));
        }
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }
}
