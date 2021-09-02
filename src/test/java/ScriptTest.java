import io.github.bitcoineducation.bitcoinjava.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Security;
import java.util.List;

import static io.github.bitcoineducation.bitcoinjava.OpCodes.*;
import static java.math.BigInteger.valueOf;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ScriptTest {
    @Test
    public void parse() throws IOException {
        String scriptPubkey = "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937";
        Script script = Script.fromByteStream(new ByteArrayInputStream(Hex.decode(scriptPubkey)));
        String cmd0 = "304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601";
        assertEquals(cmd0, script.getCommands().get(0));
        String cmd1 = "035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937";
        assertEquals(cmd1, script.getCommands().get(1));
    }

    @Test
    public void serialize() throws IOException {
        String scriptPubkey = "6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937";
        Script script = Script.fromByteStream(new ByteArrayInputStream(Hex.decode(scriptPubkey)));
        assertEquals(scriptPubkey, script.serialize());
    }

    @Test
    public void rawSerialize() {
        String pubkey1 = "022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70";
        String pubkey2 = "03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71";
        String expectedResult = "5221022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb702103b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb7152ae";
        Script script = new Script(List.of(valueOf(OP_2), pubkey1, pubkey2, valueOf(OP_2), valueOf(OP_CHECKMULTISIG)));
        assertEquals(expectedResult, script.rawSerialize());
    }

    @Test
    public void p2shAddress() {
        Security.addProvider(new BouncyCastleProvider());
        String pubkey1 = "022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70";
        String pubkey2 = "03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71";
        Script redeemScript = new Script(List.of(valueOf(OP_2), pubkey1, pubkey2, valueOf(OP_2), valueOf(OP_CHECKMULTISIG)));
        assertEquals("3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh", redeemScript.p2shAddress(AddressConstants.MAINNET_P2SH_ADDRESS_PREFIX));
    }

    @Test
    public void p2shP2wpkhAddress() {
        PrivateKey privateKey = PrivateKey.fromWif("L46JDUzM92EhyG3eeTbczaDzph1S6yANmRDeBKVaWa2vH1h77z4e", true);
        String address = Script.p2wpkhScript(Hash160.hashToHex(privateKey.getPublicKey().getCompressedPublicKey())).p2shAddress(AddressConstants.MAINNET_P2SH_ADDRESS_PREFIX);
        assertEquals("3Ko5pX4ZcqtCXPqJB1FsC821SWt3C4Msoo", address);
    }

    @Test
    public void p2wpkhScript() {
        Script script = Script.p2wpkhScript("751e76e8199196d454941c45d1b3a323f1433bd6");
        assertEquals("0014751e76e8199196d454941c45d1b3a323f1433bd6", script.rawSerialize());
    }

    @Test
    public void p2shScript() {
        String address = "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC";
        String h160 = Base58.decodeWithChecksumToHex(address);
        Script script = Script.p2shScript(h160);
        assertEquals("a914f815b036d9bbbce5e9f2a00abd1bf3dc91e9551087", script.rawSerialize());
    }

    @Test
    public void p2shScript2() {
        Script redeemScript = new Script(List.of(
            valueOf(OP_2),
            "0491bba2510912a5bd37da1fb5b1673010e43d2c6d812c514e91bfa9f2eb129e1c183329db55bd868e209aac2fbc02cb33d98fe74bf23f0c235d6126b1d8334f86",
            "04865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac09ef122b1a986818a7cb624532f062c1d1f8722084861c5c3291ccffef4ec6874",
            "048d2455d2403e08708fc1f556002f1b6cd83f992d085097f9974ab08a28838f07896fbab08f39495e15fa6fad6edbfb1e754e35fa1c7844c41f322a1863d46213",
            valueOf(OP_3),
            valueOf(OP_CHECKMULTISIG))
        );
        assertEquals("3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC", redeemScript.p2shAddress(AddressConstants.MAINNET_P2SH_ADDRESS_PREFIX));
    }

    @Test
    public void p2wshScript() {
        Script redeemScript = new Script(List.of(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            valueOf(OP_CHECKSIG)
        ));
        assertEquals("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", redeemScript.p2wshAddress(AddressConstants.MAINNET_P2WPKH_ADDRESS_PREFIX));
    }

    @Test
    public void p2wshScript2() {
        Script redeemScript = new Script(List.of(
            "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            valueOf(OP_CHECKSIG)
        ));
        assertEquals("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", redeemScript.p2wshAddress(AddressConstants.TESTNET_P2WPKH_ADDRESS_PREFIX));
    }
}
