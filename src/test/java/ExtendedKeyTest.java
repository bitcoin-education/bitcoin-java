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

    @ParameterizedTest
    @MethodSource("vector2Parameters")
    public void vector2(String expectedSerializedExtendedKey, ExtendedKey extendedKey) throws NoSuchAlgorithmException {
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
                masterPrivateKey.ckd(BigInteger.ZERO, true, true, "mainnet")
            ),
            Arguments.of(
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
                masterPrivateKey.ckd(BigInteger.ZERO, false, true, "mainnet")
            ),
            Arguments.of(
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                masterPrivateKey.ckd("0'/1", true,  "mainnet")
            ),
            Arguments.of(
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
                masterPrivateKey.ckd("0'/1", false,  "mainnet")
            )
        );
    }

    private static Stream<Arguments> vector2Parameters() throws NoSuchAlgorithmException {
        byte[] seed = Hex.decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
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
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                masterPrivateKey
            ),
            Arguments.of(
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
                masterPubkey
            ),
            Arguments.of(
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                masterPrivateKey.ckd(BigInteger.ZERO, true, false, "mainnet")
            ),
            Arguments.of(
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
                masterPrivateKey.ckd(BigInteger.ZERO, false, false, "mainnet")
            )
        );
    }

}
