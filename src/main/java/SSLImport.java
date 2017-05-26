import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;



public class SSLImport {
    /**
     * Simple pattern, can be more sophisticated by checking the suffixes.
     */
    public static final Pattern fqdnPattern        = Pattern.compile("^\\w+(\\.\\w+)+$");
    public static final Pattern decimalBytePattern = Pattern.compile("\\d{1,2}|1\\d{2}|2[0-4]\\d|25[0-5]");
    public static final Pattern ipv4Pattern        = Pattern.compile("("+decimalBytePattern.pattern()+")\\."+
                                                                     "("+decimalBytePattern.pattern()+")\\."+
                                                                     "("+decimalBytePattern.pattern()+")\\."+
                                                                     "("+decimalBytePattern.pattern()+")");


    public static String host      = "maven.lshl.org";
    public static int    port      = 443;
    public static String storePath = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security";
    public static String storeName = "cacerts";


    private static void verifyArgs(File ksFile) throws IOException {
        //verify key store
        if (!ksFile.exists()) {
            throw new FileNotFoundException("KeyStore file '"+ksFile+"' not found");
        }
        if (!ksFile.isFile()) {
            throw new FileNotFoundException("KeyStore is not a file '"+ksFile+"'!");
        }
        if (!ksFile.canRead()) {
            throw new IOException("KeyStore file '"+ksFile+"' is not readable!");
        }
        if (!ksFile.canWrite()) {
            throw new IOException("KeyStore file '"+ksFile+"' is not writeable!");
        }
    }

    public static void main(String[] args) throws Exception {
        parseArgs(args);
        File ksFile = new File(storePath, storeName);
        verifyArgs(ksFile);

        SSLContext          context = SSLContext.getInstance("TLS");
        SSLSocketFactory    factory = context.getSocketFactory();
        System.out.println("Connecting "+host+":"+port);
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
    }

    private static void printUsage() {
        System.out.println("java SSLImport [--site <fqdn_or_ip>] [--port <port num>]");
        System.out.println("java SSLImport --help");
    }

    private static void parseHost(String host_) {
        Matcher m = fqdnPattern.matcher(host_);
        if (null!=m) {
            if (m.matches()) {
                host = host_;
                return;
            }
        }
        m = ipv4Pattern.matcher(host_);
        if (null!=m) {
            if (m.matches()) {
                host = host_;
            }
        }
        throw new IllegalArgumentException("Invalid host '"+host+"'");
    }

    private static void processKeystore(String keyStore) throws IOException {
        File f = new File(keyStore);
        if (!f.exists()) {
            throw new FileNotFoundException("File/Directory '"+keyStore+"' does not exist");
        }
        if (f.isDirectory()) {
            f = new File(f, storeName);
            if (!f.exists()) {
                throw new FileNotFoundException("File '"+f+"' does not exist");
            }
            if (!f.isFile()) {
                throw new FileNotFoundException("File '"+f+"' is not a file!");
            }
            storePath = keyStore;
            return;
        }
        if (f.isFile()) {
            File d = f.getParentFile();
            if (null==d) {
                throw new IOException("Something went wrong null parent for '"+f+"'");
            }
            if (!d.exists()) {
                throw new IOException("Something went wrong parrent doesn't exist for '"+f+"'");
            }
            if (!d.isDirectory()) {
                throw new IOException("Something went wrong parrent not a directory for '"+f+"'");
            }
            storePath = d.getAbsolutePath();
            storeName = f.getName();
            return;
        }
        throw new IllegalArgumentException("Bad keyStore argument '"+keyStore+"'");
    }

    private static void parseArgs(String[] args) throws IOException {
        for (int i=0;i<args.length;++i) {
            if ("--help".equals(args[i])) {
                printUsage();
                System.exit(0);
                continue;
            }
            if ("--host".equals(args[i])) {
                if (args.length<i+2) {
                    System.err.println("Missing argument for --host ("+i+")!");
                    System.exit(1);
                }
                ++i;
                parseHost(args[i]);
            }
            if ("--port".equals(args[i])) {
                if (args.length<i+2) {
                    System.err.println("Missing argument for --port ("+i+")!");
                    System.exit(1);
                }
                ++i;
                port = Integer.parseInt(args[i]);
            }
            if ("--keystore".equals(args[i])) {
                if (args.length<i+2) {
                    System.err.println("Missing argument for --keystore ("+i+")!");
                    System.exit(1);
                }
                ++i;
                processKeystore(args[i]);
            }
        }
    }
}


