package io.github.bitcoineducation.bitcoinjava;

import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import static java.math.BigInteger.TWO;
import static java.math.BigInteger.ZERO;

public class PrivateKey {
    private final BigInteger secret;

    private final PublicKey publicKey;

    public PrivateKey(BigInteger secret) {
        this.secret = secret;
        this.publicKey = new PublicKey(SecP256K1.G.multiply(secret).normalize());
    }

    public static PrivateKey fromWif(String wif, boolean compressed) {
        byte[] bytes = Base58.decodeWif(wif, compressed);
        return new PrivateKey(BigIntegers.fromUnsignedByteArray(bytes));
    }

    public BigInteger getSecret() {
        return secret;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String wif(String prefix, boolean compressed) {
        byte[] secretBytes = BigIntegers.asUnsignedByteArray(32, secret);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decodeStrict(prefix));
        byteArrayOutputStream.writeBytes(secretBytes);
        if (compressed) {
            byteArrayOutputStream.writeBytes(Hex.decodeStrict("01"));
        }
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    public PrivateKey toTaprootTweakSeckey(BigInteger h) {
        BigInteger secretKey = secret;
        if (!publicKey.getPoint().getAffineYCoord().toBigInteger().mod(TWO).equals(ZERO)) {
            secretKey = SecP256K1.order.subtract(secretKey);
        }
        BigInteger t = TaggedHash.hashToBigInteger("TapTweak", BigIntegers.asUnsignedByteArray(publicKey.getX().add(h)));
        return new PrivateKey(secretKey.add(t).mod(SecP256K1.order));
    }
}
