package bitcoinjava;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.valueOf;

public class SecP256K1 {
    public static final BigInteger order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
    public static final SecP256K1Curve curve = new SecP256K1Curve();
    public static final ECPoint G = curve.createPoint(
        new BigInteger(1, Hex.decodeStrict("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
        new BigInteger(1, Hex.decodeStrict("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    );
    public static final ECDomainParameters ecDomainParameters = new ECDomainParameters(SecP256K1.curve, SecP256K1.G, SecP256K1.order);

    public static ECFieldElement pow(ECFieldElement x, BigInteger exponent) {
        BigInteger n = exponent.mod(SecP256K1.curve.getQ().subtract(ONE));
        BigInteger num = x.toBigInteger().modPow(n, SecP256K1.curve.getQ());
        return new SecP256K1FieldElement(num);
    }

    public static ECFieldElement sqrt(ECFieldElement x) {
        return pow(x, SecP256K1FieldElement.Q.add(ONE).divide(valueOf(4)));
    }
}
