package CryptoLogic;

import java.io.StringReader;
import java.io.StringWriter;
import java.util.Properties;

public final class KvMessage {
    private KvMessage() {}

    public static String encode(Properties properties) throws Exception {
        StringWriter writer = new StringWriter();
        properties.store(writer, null);
        return writer.toString();
    }

    public static Properties decode(String text) throws Exception {
        Properties properties = new Properties();
        properties.load(new StringReader(text));
        return properties;
    }
}
