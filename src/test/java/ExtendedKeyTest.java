import bitcoinjava.ExtendedKey;
import bitcoinjava.HMacSha512;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ExtendedKeyTest {
    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @ParameterizedTest
    @MethodSource("vector1Parameters")
    public void vector1(String expectedSerializedExtendedKey, ExtendedKey extendedKey) throws NoSuchAlgorithmException {
        assertEquals(expectedSerializedExtendedKey, extendedKey.serialize());
    }

    private static Stream<Arguments> vector1Parameters() throws NoSuchAlgorithmException {
        byte[] seed = Hex.decode("000102030405060708090a0b0c0d0e0f");
        ExtendedKey masterPrivateKey = ExtendedKey.from(
            HMacSha512.hash("Bitcoin seed", seed),
            true,
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        ExtendedKey masterPubkey = ExtendedKey.from(
            HMacSha512.hash("Bitcoin seed", seed),
            false,
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        return Stream.of(
            Arguments.of(
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                masterPrivateKey
            ),
            Arguments.of(
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                masterPubkey
            ),
            Arguments.of(
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                masterPrivateKey.ckd(BigInteger.ZERO, true, true)
            ),
            Arguments.of(
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                masterPrivateKey.ckd(BigInteger.ZERO, false, true)
            )
        );
    }

}
