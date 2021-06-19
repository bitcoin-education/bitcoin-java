import bitcoinjava.Base58;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import bitcoinjava.Script;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

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
    public void p2wpkhScript() {
        Script script = Script.p2wpkhScript("751e76e8199196d454941c45d1b3a323f1433bd6");
        assertEquals("0014751e76e8199196d454941c45d1b3a323f1433bd6", script.rawSerialize());
    }

    @Test
    public void p2shScript() throws NoSuchAlgorithmException {
        String address = "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC";
        String h160 = Base58.decodeWithChecksumToHex(address);
        Script script = Script.p2shScript(h160);
        assertEquals("a914f815b036d9bbbce5e9f2a00abd1bf3dc91e9551087", script.rawSerialize());
    }
}
