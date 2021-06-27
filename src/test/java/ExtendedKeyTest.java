import bitcoinjava.ExtendedKey;
import bitcoinjava.ExtendedPrivateKey;
import bitcoinjava.ExtendedPubkey;
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
    public void vector1(String expectedSerializedExtendedKey, ExtendedKey extendedPrivateKey) throws NoSuchAlgorithmException {
        assertEquals(expectedSerializedExtendedKey, extendedPrivateKey.serialize());
    }

    @ParameterizedTest
    @MethodSource("vector2Parameters")
    public void vector2(String expectedSerializedExtendedKey, ExtendedKey extendedPrivateKey) throws NoSuchAlgorithmException {
        assertEquals(expectedSerializedExtendedKey, extendedPrivateKey.serialize());
    }

    @ParameterizedTest
    @MethodSource("vector3Parameters")
    public void vector3(String expectedSerializedExtendedKey, ExtendedKey extendedPrivateKey) throws NoSuchAlgorithmException {
        assertEquals(expectedSerializedExtendedKey, extendedPrivateKey.serialize());
    }

    @ParameterizedTest
    @MethodSource("vector4Parameters")
    public void vector4(String expectedSerializedExtendedKey, ExtendedKey extendedPrivateKey) throws NoSuchAlgorithmException {
        assertEquals(expectedSerializedExtendedKey, extendedPrivateKey.serialize());
    }

    @ParameterizedTest
    @MethodSource("fromPublicKeyParameters")
    public void fromPublicKey(String expectedSerializedExtendedKey, ExtendedKey extendedPubkey) throws NoSuchAlgorithmException {
        assertEquals(expectedSerializedExtendedKey, extendedPubkey.serialize());
    }

    private static Stream<Arguments> vector1Parameters() throws NoSuchAlgorithmException {
        byte[] seed = Hex.decode("000102030405060708090a0b0c0d0e0f");
        ExtendedPrivateKey masterPrivateKey = ExtendedPrivateKey.from(
            HMacSha512.hash("Bitcoin seed", seed),
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        ExtendedPubkey masterPubkey = ExtendedPubkey.fromPrivate(
            HMacSha512.hash("Bitcoin seed", seed),
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
            ),
            Arguments.of(
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                masterPrivateKey.ckd("0'/1/2'", true,  "mainnet")
            ),
            Arguments.of(
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
                masterPrivateKey.ckd("0'/1/2'", false,  "mainnet")
            ),
            Arguments.of(
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                masterPrivateKey.ckd("0'/1/2'/2", true,  "mainnet")
            ),
            Arguments.of(
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
                masterPrivateKey.ckd("0'/1/2'/2", false,  "mainnet")
            ),
            Arguments.of(
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                masterPrivateKey.ckd("0'/1/2'/2/1000000000", true,  "mainnet")
            ),
            Arguments.of(
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
                masterPrivateKey.ckd("0'/1/2'/2/1000000000", false,  "mainnet")
            )
        );
    }

    private static Stream<Arguments> vector2Parameters() throws NoSuchAlgorithmException {
        byte[] seed = Hex.decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542");
        ExtendedPrivateKey masterPrivateKey = ExtendedPrivateKey.from(
            HMacSha512.hash("Bitcoin seed", seed),
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        ExtendedPubkey masterPubkey = ExtendedPubkey.fromPrivate(
            HMacSha512.hash("Bitcoin seed", seed),
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
            ),
            Arguments.of(
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                masterPrivateKey.ckd("0/2147483647'", true, "mainnet")
            ),
            Arguments.of(
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
                masterPrivateKey.ckd("0/2147483647'", false, "mainnet")
            ),
            Arguments.of(
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                masterPrivateKey.ckd("0/2147483647'/1", true, "mainnet")
            ),
            Arguments.of(
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
                masterPrivateKey.ckd("0/2147483647'/1", false, "mainnet")
            ),
            Arguments.of(
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                masterPrivateKey.ckd("0/2147483647'/1/2147483646'", true, "mainnet")
            ),
            Arguments.of(
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
                masterPrivateKey.ckd("0/2147483647'/1/2147483646'", false, "mainnet")
            ),
            Arguments.of(
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                masterPrivateKey.ckd("0/2147483647'/1/2147483646'/2", true, "mainnet")
            ),
            Arguments.of(
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
                masterPrivateKey.ckd("0/2147483647'/1/2147483646'/2", false, "mainnet")
            )
        );
    }

    private static Stream<Arguments> vector3Parameters() throws NoSuchAlgorithmException {
        byte[] seed = Hex.decode("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be");
        ExtendedPrivateKey masterPrivateKey = ExtendedPrivateKey.from(
            HMacSha512.hash("Bitcoin seed", seed),
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        ExtendedPubkey masterPubkey = ExtendedPubkey.fromPrivate(
            HMacSha512.hash("Bitcoin seed", seed),
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        return Stream.of(
            Arguments.of(
                "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                masterPrivateKey
            ),
            Arguments.of(
                "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
                masterPubkey
            ),
            Arguments.of(
                "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                masterPrivateKey.ckd("0'", true, "mainnet")
            ),
            Arguments.of(
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
                masterPrivateKey.ckd("0'", false, "mainnet")
            )
        );
    }

    private static Stream<Arguments> vector4Parameters() throws NoSuchAlgorithmException {
        byte[] seed = Hex.decode("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678");
        ExtendedPrivateKey masterPrivateKey = ExtendedPrivateKey.from(
            HMacSha512.hash("Bitcoin seed", seed),
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        ExtendedPubkey masterPubkey = ExtendedPubkey.fromPrivate(
            HMacSha512.hash("Bitcoin seed", seed),
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        return Stream.of(
            Arguments.of(
                "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
                masterPrivateKey
            ),
            Arguments.of(
                "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
                masterPubkey
            ),
            Arguments.of(
                "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                masterPrivateKey.ckd("0'", true, "mainnet")
            ),
            Arguments.of(
                "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
                masterPrivateKey.ckd("0'", false, "mainnet")
            ),
            Arguments.of(
                "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                masterPrivateKey.ckd("0'/1'", true, "mainnet")
            ),
            Arguments.of(
                "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
                masterPrivateKey.ckd("0'/1'", false, "mainnet")
            )
        );
    }

    private static Stream<Arguments> fromPublicKeyParameters() throws NoSuchAlgorithmException {
        byte[] seed = Hex.decode("12299dcf3e1a6368bddbaf4dd1cd83552edb6fc2c41ec081d7fe58c9f0aca9fb37d6d3d3cd275f088b484a52a37f5c8781f6d20547744cd525fb9940b7dbdfce");
        ExtendedPubkey masterPubkey = ExtendedPubkey.fromPrivate(
            HMacSha512.hash("Bitcoin seed", seed),
            "mainnet",
            0,
            "00000000",
            BigInteger.ZERO
        );
        return Stream.of(
            Arguments.of(
                "xpub661MyMwAqRbcEqsg3NugDbqxMH7xDg8jaYD5AL1T7JgQADPgvqDVSWZfuAzcG3PCTRc48VU5mMfRzY9KL469j5KVs3iAosht6HueU5CKYNh",
                masterPubkey
            ),
            Arguments.of(
                "xpub68SSAVjmWkaMdA5HMd4aYszjo3H8Qy6URd69fBBcgCSFt1j8XGWudstUc8ULx8BZDkCnNVJcsbudGGzTnHEUdiYRTKE2G42EyoVDQrexD9G",
                masterPubkey.ckd(BigInteger.ZERO, false, false, "mainnet")
            ),
            Arguments.of(
                "xpub69qBbjK3W1MYD5Q2KP14t1i1Vn1tWmLzfwccrNV3Zz7e9cV4kU5P5nQGMbJYzyXpyWxciAb1bqRiEPS6C8yfYiouDxK2jB1FuadRh1RcV1J",
                masterPubkey.ckd("0/1", "mainnet")
            ),
            Arguments.of(
                "xpub6CNQehfrZtL2UrDfB8dR9zZesBXdinqNgJhTWmhRf1Kdnm9KVgnn1rt9mWMXedjt4hMZrK9GVtKnap4w8PUXac77htBdvhqs6CxEHA8qiRu",
                masterPubkey.ckd("0/1/2", "mainnet")
            ),
            Arguments.of(
                "xpub6G4WGYbpiiraTi2yMb3Lrp2cw1uZ2KkKK1ENzGm8DzZVzHRgya62RyPNHpcHQV76eQeYv5aHiZkgZWR9gHAxBnFaFqhg3NKt3sXeajh63hD",
                masterPubkey.ckd("0/2147483647/1/2147483646/2", "mainnet")
            )
        );
    }

}
