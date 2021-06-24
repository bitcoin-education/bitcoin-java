package bitcoinjava;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.util.encoders.Hex;

public class MnemonicSeed {
    private final String sentence;

    public MnemonicSeed(String sentence) {
        this.sentence = sentence;
    }

    public String getSentence() {
        return sentence;
    }

    public byte[] toSeed(String passphrase) {
        PKCS5S2ParametersGenerator pkcs5S2ParametersGenerator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA512());
        pkcs5S2ParametersGenerator.init(
            PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(sentence.toCharArray()),
            PBEParametersGenerator.PKCS5PasswordToUTF8Bytes("mnemonic".concat(passphrase).toCharArray()),
            2048
        );
        return ((KeyParameter) pkcs5S2ParametersGenerator.generateDerivedParameters(512)).getKey();
    }

    public String toSeedHex(String passphrase) {
        return Hex.toHexString(toSeed(passphrase));
    }

    public ExtendedKey toMasterKey(String passphrase, String environment) {
        return ExtendedKey.from(
            HMacSha512.hash("Bitcoin seed", toSeed(passphrase)),
            true,
            environment,
            0,
            "00000000",
            0
        );
    }

}
