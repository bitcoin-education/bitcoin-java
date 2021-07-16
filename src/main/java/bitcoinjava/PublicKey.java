package bitcoinjava;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

import static bitcoinjava.BIP340.liftX;
import static bitcoinjava.SecP256K1.*;
import static java.math.BigInteger.*;

public class PublicKey {
    private final byte[] uncompressedPublicKey;

    private final byte[] compressedPublicKey;

    private final ECPoint point;

    public PublicKey(ECPoint point) {
        this.point = point;
        this.uncompressedPublicKey = uncompressedPublicKey(point);
        this.compressedPublicKey = compressedPublicKey(point);
    }

    public static PublicKey fromCompressedPublicKey(byte[] compressedPublicKey) {
        BigInteger x = new BigInteger(1, ByteUtils.subArray(compressedPublicKey, 1, 33));
        SecP256K1FieldElement xElement = new SecP256K1FieldElement(x);

        boolean isEven = compressedPublicKey[0] == 2;
        ECFieldElement alpha = pow(xElement, valueOf(3)).add(new SecP256K1FieldElement(valueOf(7)));
        ECFieldElement beta = sqrt(alpha);
        ECFieldElement evenBeta;
        ECFieldElement oddBeta;
        if (beta.toBigInteger().mod(TWO).equals(ZERO)) {
            evenBeta = beta;
            oddBeta = new SecP256K1FieldElement(SecP256K1FieldElement.Q.subtract(beta.toBigInteger()));
        } else {
            oddBeta = beta;
            evenBeta = new SecP256K1FieldElement(SecP256K1FieldElement.Q.subtract(beta.toBigInteger()));
        }
        if (isEven) {
            return new PublicKey(SecP256K1.curve.createPoint(x, evenBeta.toBigInteger()).normalize());
        }
        return new PublicKey(SecP256K1.curve.createPoint(x, oddBeta.toBigInteger()).normalize());
    }

    public PublicKey toTaprootInternalKey() {
        return taprootInternalKeyFromX(getX());
    }

    public PublicKey toTaprootSingleKeyOutputKey() {
        return new PublicKey(
            G.multiply(TaggedHash.hashToBigInteger("TapTweak", BigIntegers.asUnsignedByteArray(getX()))).add(this.point).normalize()
        );
    }

    public static PublicKey taprootInternalKeyFromX(BigInteger x) {
        return new PublicKey(liftX(x));
    }

    private byte[] uncompressedPublicKey(ECPoint point) {
        return point.getEncoded(false);
    }

    private byte[] compressedPublicKey(ECPoint point) {
        return point.getEncoded(true);
    }

    public String uncompressedPublicKeyHex() {
        return Hex.toHexString(uncompressedPublicKey);
    }

    public String compressedPublicKeyHex() {
        return Hex.toHexString(compressedPublicKey);
    }

    public String addressFromUncompressedPublicKey(String prefix) {
        byte[] hash160 = Hash160.hash(uncompressedPublicKey);
        return concat(prefix, hash160);
    }

    public String addressFromCompressedPublicKey(String prefix) {
        byte[] hash160 = Hash160.hash(compressedPublicKey);
        return concat(prefix, hash160);
    }

    public String segwitAddressFromCompressedPublicKey(String prefix) {
        byte[] hash160 = Hash160.hash(compressedPublicKey);
        return Bech32.encode(prefix, 0, hash160);
    }

    public String taprootAddress(String prefix) {
        return Bech32.encode(prefix, 1, point.getAffineXCoord().getEncoded());
    }

    private String concat(String prefix, byte[] hash160) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(Hex.decodeStrict(prefix));
        byteArrayOutputStream.writeBytes(hash160);
        return Base58.encodeWithChecksum(byteArrayOutputStream.toByteArray());
    }

    public byte[] getCompressedPublicKey() {
        return compressedPublicKey;
    }

    public byte[] getUncompressedPublicKey() {
        return uncompressedPublicKey;
    }

    public ECPoint getPoint() {
        return point;
    }

    public BigInteger getX() {
        return point.getAffineXCoord().toBigInteger();
    }

    public String getXHex() {
        return Hex.toHexString(BigIntegers.asUnsignedByteArray(getX()));
    }
}
