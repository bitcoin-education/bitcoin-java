package bitcoinjava;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;

import java.math.BigInteger;

import static bitcoinjava.SecP256K1.*;
import static java.math.BigInteger.*;

public class BIP340 {
    public static ECPoint liftX(BigInteger pubKeyX) {
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
}
