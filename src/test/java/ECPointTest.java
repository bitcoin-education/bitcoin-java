import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.stream.Stream;

import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.*;

public class ECPointTest {
    @Test
    public void validateECPoints() {
        ECCurve.Fp curve = new ECCurve.Fp(valueOf(223), valueOf(0), valueOf(7), null, null);
        curve.validatePoint(valueOf(192), valueOf(105));
        curve.validatePoint(valueOf(17), valueOf(56));
        curve.validatePoint(valueOf(1), valueOf(193));
    }

    @Test
    public void invalidECPoints() {
        ECCurve.Fp curve = new ECCurve.Fp(valueOf(223), valueOf(0), valueOf(7), null, null);
        assertThrows(IllegalArgumentException.class, () -> curve.validatePoint(valueOf(200), valueOf(119)));
        assertThrows(IllegalArgumentException.class, () -> curve.validatePoint(valueOf(42), valueOf(99)));
    }

    @ParameterizedTest
    @MethodSource("addECPointsParameters")
    public void addECPoints(ECPoint p1, ECPoint p2, ECPoint expectedResult) {
        ECPoint result = p1.add(p2).normalize();
        assertEquals(expectedResult, result);
    }

    @ParameterizedTest
    @MethodSource("scalarMultiplyECPointsParameters")
    public void scalarMultiplyECPoints(ECPoint p1, BigInteger scalar, ECPoint expectedResult) {
        ECPoint result = p1.multiply(scalar).normalize();
        assertEquals(expectedResult, result);
    }

    @Test
    public void SecP256k1PointTest() {
        BigInteger order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
        SecP256K1Curve curve = new SecP256K1Curve();
        ECPoint point = curve.createPoint(
            new BigInteger(1, Hex.decodeStrict("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            new BigInteger(1, Hex.decodeStrict("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        );
        assertTrue(point.multiply(order).equals(curve.getInfinity()));
    }

    @ParameterizedTest
    @MethodSource("SecP256k1ECDSASignatureTestParameters")
    public void SecP256k1ECDSASignatureVerifyTest(BigInteger z, BigInteger r, BigInteger s, ECPoint point) {
        BigInteger order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
        SecP256K1Curve curve = new SecP256K1Curve();
        ECPoint G = curve.createPoint(
            new BigInteger(1, Hex.decodeStrict("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            new BigInteger(1, Hex.decodeStrict("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        );
        BigInteger sInv = s.modPow(order.subtract(valueOf(2)), order);
        BigInteger u = z.multiply(sInv).mod(order);
        BigInteger v = r.multiply(sInv).mod(order);

        assertEquals(G.multiply(u).add(point.multiply(v)).normalize().getAffineXCoord().toBigInteger(), r);
    }

    @ParameterizedTest
    @MethodSource("SecP256k1ECDSASignatureTestParameters")
    public void SecP256k1ECDSASignatureVerify2Test(BigInteger z, BigInteger r, BigInteger s, ECPoint point) {
        BigInteger order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
        SecP256K1Curve curve = new SecP256K1Curve();
        ECPoint G = curve.createPoint(
            new BigInteger(1, Hex.decodeStrict("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            new BigInteger(1, Hex.decodeStrict("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        );
        ECDSASigner ecdsaSigner = new ECDSASigner();
        ecdsaSigner.init(false, new ECPublicKeyParameters(point, new ECDomainParameters(curve, G, order)));
        ecdsaSigner.verifySignature(z.toByteArray(), r, s);
    }

    @ParameterizedTest
    @MethodSource("SecP256k1ECDSASignatureCreateTestParams")
    public void SecP256k1ECDSASignatureCreateTest(
        Object secret,
        String message,
        String expectedPointX,
        String expectedPointY,
        String expectedZ,
        String expectedR,
        String expectedS
    ) throws NoSuchAlgorithmException {
        BigInteger order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
        SecP256K1Curve curve = new SecP256K1Curve();
        ECPoint G = curve.createPoint(
            new BigInteger(1, Hex.decodeStrict("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            new BigInteger(1, Hex.decodeStrict("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        );
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        BigInteger e;
        if (secret instanceof String) {
            e = new BigInteger(1, messageDigest.digest(messageDigest.digest(((String) secret).getBytes(StandardCharsets.UTF_8))));
        } else {
            e = valueOf(((Long) secret));
        }
        byte[] zBytes = messageDigest.digest(messageDigest.digest(message.getBytes(StandardCharsets.UTF_8)));
        BigInteger z = new BigInteger(1, zBytes);
        BigInteger k = valueOf(1234567890);
        ECDSASigner ecdsaSigner = new ECDSASigner(new DSAKCalculator() {
            @Override
            public boolean isDeterministic() {
                return true;
            }

            @Override
            public void init(BigInteger n, SecureRandom random) {

            }

            @Override
            public void init(BigInteger n, BigInteger d, byte[] message) {

            }

            @Override
            public BigInteger nextK() {
                return k;
            }
        });
        ecdsaSigner.init(true, new ECPrivateKeyParameters(e, new ECDomainParameters(curve, G, order)));

        ECPoint point = G.multiply(e).normalize();
        assertEquals(new BigInteger(1, Hex.decodeStrict(expectedPointX)), point.getAffineXCoord().toBigInteger());
        assertEquals(new BigInteger(1, Hex.decodeStrict(expectedPointY)), point.getAffineYCoord().toBigInteger());
        assertEquals(expectedZ, z.toString(16));

        BigInteger[] signature = ecdsaSigner.generateSignature(zBytes);
        assertEquals(expectedR, signature[0].toString(16));
        assertEquals(expectedS, signature[1].toString(16));
    }

    private static Stream<Arguments> addECPointsParameters() {
        ECCurve.Fp curve = new ECCurve.Fp(valueOf(223), valueOf(0), valueOf(7), null, null);
        return Stream.of(
            Arguments.of(
                curve.createPoint(valueOf(192), valueOf(105)),
                curve.createPoint(valueOf(17), valueOf(56)),
                curve.createPoint(valueOf(170), valueOf(142))
            ),
            Arguments.of(
                curve.createPoint(valueOf(170), valueOf(142)),
                curve.createPoint(valueOf(60), valueOf(139)),
                curve.createPoint(valueOf(220), valueOf(181))
            ),
            Arguments.of(
                curve.createPoint(valueOf(47), valueOf(71)),
                curve.createPoint(valueOf(17), valueOf(56)),
                curve.createPoint(valueOf(215), valueOf(68))
            ),
            Arguments.of(
                curve.createPoint(valueOf(143), valueOf(98)),
                curve.createPoint(valueOf(76), valueOf(66)),
                curve.createPoint(valueOf(47), valueOf(71))
            )
        );
    }

    private static Stream<Arguments> scalarMultiplyECPointsParameters() {
        ECCurve.Fp curve = new ECCurve.Fp(valueOf(223), valueOf(0), valueOf(7), null, null);
        return Stream.of(
            Arguments.of(
                curve.createPoint(valueOf(192), valueOf(105)),
                valueOf(2),
                curve.createPoint(valueOf(49), valueOf(71))
            ),
            Arguments.of(
                curve.createPoint(valueOf(143), valueOf(98)),
                valueOf(2),
                curve.createPoint(valueOf(64), valueOf(168))
            ),
            Arguments.of(
                curve.createPoint(valueOf(47), valueOf(71)),
                valueOf(2),
                curve.createPoint(valueOf(36), valueOf(111))
            ),
            Arguments.of(
                curve.createPoint(valueOf(47), valueOf(71)),
                valueOf(4),
                curve.createPoint(valueOf(194), valueOf(51))
            ),
            Arguments.of(
                curve.createPoint(valueOf(47), valueOf(71)),
                valueOf(8),
                curve.createPoint(valueOf(116), valueOf(55))
            ),
            Arguments.of(
                curve.createPoint(valueOf(47), valueOf(71)),
                valueOf(21),
                curve.getInfinity()
            ),
            Arguments.of(
                curve.createPoint(valueOf(47), valueOf(71)),
                valueOf(23),
                curve.createPoint(valueOf(36), valueOf(111))
            )
        );
    }

    private static Stream<Arguments> SecP256k1ECDSASignatureTestParameters() {
        SecP256K1Curve curve = new SecP256K1Curve();
        return Stream.of(
            Arguments.of(
                new BigInteger(1, Hex.decodeStrict("bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423")),
                new BigInteger(1, Hex.decodeStrict("37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6")),
                new BigInteger(1, Hex.decodeStrict("8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec")),
                curve.createPoint(
                    new BigInteger(1, Hex.decodeStrict("04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574")),
                    new BigInteger(1, Hex.decodeStrict("82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4"))
                )
            ),
            Arguments.of(
                new BigInteger(1, Hex.decodeStrict("ec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60")),
                new BigInteger(1, Hex.decodeStrict("ac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395")),
                new BigInteger(1, Hex.decodeStrict("068342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4")),
                curve.createPoint(
                    new BigInteger(1, Hex.decodeStrict("887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c")),
                    new BigInteger(1, Hex.decodeStrict("61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"))
                )
            ),
            Arguments.of(
                new BigInteger(1, Hex.decodeStrict("7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d")),
                new BigInteger(1, Hex.decodeStrict("eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c")),
                new BigInteger(1, Hex.decodeStrict("c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6")),
                curve.createPoint(
                    new BigInteger(1, Hex.decodeStrict("887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c")),
                    new BigInteger(1, Hex.decodeStrict("61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34"))
                )
            )
        );
    }

    private static Stream<Arguments> SecP256k1ECDSASignatureCreateTestParams() {
        return Stream.of(
            Arguments.of(
                "my secret",
                "my message",
                "028d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52",
                "0ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2",
                "231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78",
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
                "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9"
            ),
            Arguments.of(
                12345L,
                "Programming Bitcoin!",
                "f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f",
                "0eba29d0f0c5408ed681984dc525982abefccd9f7ff01dd26da4999cf3f6a295",
                "969f6056aa26f7d2795fd013fe88868d09c9f6aed96965016e1936ae47060d48",
                "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22",
                "1dbc63bfef4416705e602a7b564161167076d8b20990a0f26f316cff2cb0bc1a"
            )
        );
    }

}

