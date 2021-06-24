package bitcoinjava;

import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;

import java.nio.charset.StandardCharsets;

public class HMacSha512 {
    public static byte[] hash(String key, byte[] data) {
        HMac hMac = new HMac(DigestFactory.createSHA512());
        hMac.init(new KeyParameter(key.getBytes(StandardCharsets.UTF_8)));
        byte[] result = new byte[hMac.getMacSize()];
        hMac.update(data, 0, data.length);
        hMac.doFinal(result, 0);
        return result;
    }
}
