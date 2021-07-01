package bitcoinjava;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static java.math.BigInteger.TWO;
import static java.math.BigInteger.valueOf;

public class Witness {
    private List<Object> items;

    public Witness(List<Object> items) {
        this.items = items;
    }

    public static Witness fromByteStream(ByteArrayInputStream stream) throws IOException {
        BigInteger numItems;
        numItems = VarInt.fromByteStream(stream);
        ArrayList<Object> items = new ArrayList<>();
        for (int i = 0; i < numItems.intValueExact(); i++) {
            BigInteger itemLength = VarInt.fromByteStream(stream);
            if (itemLength.equals(BigInteger.ZERO)) {
                items.add(BigInteger.ZERO);
                continue;
            }
            items.add(Hex.toHexString(stream.readNBytes(itemLength.intValueExact())));
        }
        return new Witness(items);
    }

    public String serialize() {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.writeBytes(LittleEndian.fromUnsignedLittleEndian(valueOf(items.size()), 1));
        items.forEach(item -> {
            if (item instanceof BigInteger) {
                byteArrayOutputStream.writeBytes(LittleEndian.fromUnsignedLittleEndian((BigInteger) item, 1));
                return;
            }
            byteArrayOutputStream.writeBytes(VarInt.toByteStream(valueOf(((String) item).length()).divide(TWO)).readAllBytes());
            byteArrayOutputStream.writeBytes(Hex.decodeStrict((String) item));
        });
        return Hex.toHexString(byteArrayOutputStream.toByteArray());
    }

    public void appendItem(Object item) {
        items.add(item);
    }

    public List<Object> getItems() {
        return items;
    }

}
