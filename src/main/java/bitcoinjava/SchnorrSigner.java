package bitcoinjava;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static bitcoinjava.SecP256K1.*;
import static java.math.BigInteger.*;

public class SchnorrSigner {
    public static BigInteger sign(BigInteger secret, BigInteger message, BigInteger auxRand) {
        if (secret.equals(BigInteger.ZERO) || secret.compareTo(SecP256K1.order) >= 0) {
            throw new IllegalArgumentException("Secret cannot be greater than SecP256K1.order or equal 0");
        }

        ECPoint point = SecP256K1.G.multiply(secret).normalize();
        BigInteger y = point.getAffineYCoord().toBigInteger();
        if (!y.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            secret = SecP256K1.order.subtract(secret);
        }
        byte[] hashTagBIP0340Aux = hashTag("BIP0340/aux", BigIntegers.asUnsignedByteArray(32, auxRand));
        byte[] t = BigIntegers.asUnsignedByteArray(32, secret.xor(new BigInteger(1, hashTagBIP0340Aux)));
        byte[] x = point.getAffineXCoord().getEncoded();
        byte[] messageBytes = BigIntegers.asUnsignedByteArray(32, message);
        byte[] combined = ByteUtils.concatenate(ByteUtils.concatenate(t,x), messageBytes);
        byte[] randBytes = hashTag("BIP0340/nonce", combined);
        BigInteger k = new BigInteger(1, randBytes).mod(SecP256K1.order);
        if (k.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("k cannot be equal to 0");
        }
        ECPoint r = SecP256K1.G.multiply(k).normalize();
        BigInteger ry = r.getAffineYCoord().toBigInteger();
        if (!ry.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            k = SecP256K1.order.subtract(k);
        }
        byte[] rX = r.getAffineXCoord().getEncoded();
        byte[] combined2 = ByteUtils.concatenate(ByteUtils.concatenate(rX,x), messageBytes);
        BigInteger e = new BigInteger(1, hashTag("BIP0340/challenge", combined2)).mod(SecP256K1.order);

        byte[] signatureBytes = ByteUtils.concatenate(rX, BigIntegers.asUnsignedByteArray(32, k.add(e.multiply(secret)).mod(SecP256K1.order)));
        BigInteger signature = new BigInteger(1, signatureBytes);
        if (!verify(new BigInteger(1, x), message, signature)) {
            throw new IllegalArgumentException("Invalid signature");
        }
        return signature;
    }

    public static boolean verify(BigInteger pubKeyX, BigInteger message, BigInteger signature) {
        ECPoint publicKey = liftX(pubKeyX);
        if (publicKey == null) {
            return false;
        }
        byte[] signatureBytes = BigIntegers.asUnsignedByteArray(64, signature);
        byte[] r = ByteUtils.subArray(signatureBytes, 0, 32);
        if (new BigInteger(1, r).compareTo(SecP256K1.curve.getQ()) >= 0) {
            return false;
        }
        byte[] s = ByteUtils.subArray(signatureBytes, 32, 64);
        if (new BigInteger(1, s).compareTo(SecP256K1.order) >= 0) {
            return false;
        }
        byte[] pubkeyXBytes = BigIntegers.asUnsignedByteArray(32, pubKeyX);
        byte[] messageBytes = BigIntegers.asUnsignedByteArray(32, message);
        byte[] combined = ByteUtils.concatenate(ByteUtils.concatenate(r, pubkeyXBytes), messageBytes);
        BigInteger e = new BigInteger(1, hashTag("BIP0340/challenge", combined)).mod(SecP256K1.order);
        ECPoint R = G.multiply(new BigInteger(1, s)).subtract(publicKey.multiply(e)).normalize();
        if (R.isInfinity()) {
            return false;
        }
        if (!R.getAffineYCoord().toBigInteger().mod(TWO).equals(ZERO)) {
            return false;
        }
        return R.getAffineXCoord().toBigInteger().equals(new BigInteger(1, r));
    }

    private static ECPoint liftX(BigInteger pubKeyX) {
        SecP256K1FieldElement xElement;
        try {
            xElement = new SecP256K1FieldElement(pubKeyX);
        } catch (IllegalArgumentException exception) {
            return null;
        }
        ECFieldElement c = pow(xElement, valueOf(3)).add(new SecP256K1FieldElement(valueOf(7)));
        ECFieldElement y = sqrt(c);
        if (!c.toBigInteger().equals(pow(y, TWO).toBigInteger())) {
            return null;
        }
        BigInteger yNum = y.toBigInteger();
        if (!yNum.mod(TWO).equals(ZERO)) {
            yNum = curve.getQ().subtract(yNum);
        }
        return SecP256K1.curve.createPoint(pubKeyX, yNum).normalize();
    }

    private static byte[] hashTag(String tag, byte[] key) {
        byte[] shaTag = Sha256.hash(tag.getBytes(StandardCharsets.UTF_8));
        byte[] shaTags = ByteUtils.concatenate(shaTag, shaTag);
        return Sha256.hash(ByteUtils.concatenate(shaTags, key));
    }
}
