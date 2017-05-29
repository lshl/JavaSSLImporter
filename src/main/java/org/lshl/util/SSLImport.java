package org.lshl.util;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.lshl.SSLImporterVersion;



public class SSLImport implements Runnable {
    /**
     * Simple pattern, can be more sophisticated by checking the suffixes.
     */
    public static final Pattern fqdnPattern        = Pattern.compile("^\\w+(\\.\\w+)+$");
    public static final Pattern decimalBytePattern = Pattern.compile("\\d{1,2}|1\\d{2}|2[0-4]\\d|25[0-5]");
    public static final Pattern ipv4Pattern        = Pattern.compile("("+decimalBytePattern.pattern()+")\\."+
                                                                     "("+decimalBytePattern.pattern()+")\\."+
                                                                     "("+decimalBytePattern.pattern()+")\\."+
                                                                     "("+decimalBytePattern.pattern()+")");


    private String  host;
    private int     port;
    private String  storePath;
    private String  storeName;
    private String  storePass;
    private int     exitCode;
    private boolean localExport;
    private String  localStore;
    public SSLImport() {
        host        = "maven.lshl.org";
        port        = 443;
        storePath   = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security";
        storeName   = "cacerts";
        storePass   = "changeit";
        exitCode    = 0;
        localExport = false;
        localStore  = "jssecacerts";
    }


    private void verifyArgs(File ksFile, File exportKeyStore) throws IOException {
        //verify key store
        File ksDir = new File(storePath);
        if (!ksDir.exists()) {
            exitCode = 5;
            throw new FileNotFoundException("Directory '"+ksDir+"' not found!");
        }
        if (!ksDir.isDirectory()) {
            exitCode = 5;
            throw new FileNotFoundException("Directory '"+ksDir+"' is not a directory!");
        }
        if (!localExport && !ksDir.canRead()) {
            exitCode = 5;
            throw new IOException("Directory '"+ksDir+"' has no read permissions!");
        }
        if (!ksDir.canWrite()) {
            exitCode = 5;
            throw new IOException("Directory '"+ksDir+"' has no write permissions!");
        }
        if (!ksFile.exists()) {
            exitCode = 5;
            throw new FileNotFoundException("KeyStore file '"+ksFile+"' not found");
        }
        if (!ksFile.isFile()) {
            exitCode = 5;
            throw new FileNotFoundException("KeyStore is not a file '"+ksFile+"'!");
        }
        if (!ksFile.canRead()) {
            exitCode = 5;
            throw new IOException("KeyStore file '"+ksFile+"' is not readable!");
        }
        if (!ksFile.canWrite()) {
            exitCode = 5;
            throw new IOException("KeyStore file '"+ksFile+"' is not writeable!");
        }
        File esDir = exportKeyStore.getParentFile();
        if (!esDir.exists()) {
            exitCode = 5;
            throw new FileNotFoundException("Directory '"+esDir+"' not found!");
        }
        if (!esDir.isDirectory()) {
            exitCode = 5;
            throw new FileNotFoundException("Directory '"+esDir+"' is not a directory!");
        }
        if (!esDir.canRead()) {
            exitCode = 5;
            throw new IOException("Directory '"+esDir+"' has no read permissions!");
        }
        if (!esDir.canWrite()) {
            exitCode = 5;
            throw new IOException("Directory '"+esDir+"' has no write permissions!");
        }
    }

    @Override
    public void run() {
        try {
            File ksFile = new File(storePath, storeName);
            File exportKeyStore = localExport ? (new File(localStore)).getAbsoluteFile() : ksFile;
            verifyArgs(ksFile, exportKeyStore);
    
            KeyStore                  keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            TrustManagerFactory       trustFct = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            FileInputStream           fis      = new FileInputStream(ksFile);
            keyStore.load(fis, storePass.toCharArray());
            fis.close();
            trustFct.init(keyStore);
            X509TrustManager          trustMgr = (X509TrustManager) trustFct.getTrustManagers()[0];
            X509TrustManagerDecorator tmDec    = new X509TrustManagerDecorator(trustMgr);
            SSLContext                context  = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{tmDec}, null);
            SSLSocketFactory          factory  = context.getSocketFactory();
            SSLSocket                 socket   = (SSLSocket) factory.createSocket(host, port);
            try {
                socket.startHandshake();
                socket.close();
                System.out.println("Certificate already trusted");
                return;
            } catch (@SuppressWarnings("unused") SSLException e) {
                socket.close();
            }
            if (exportKeyStore.exists()) {
                @SuppressWarnings("resource")
                FileSystem fs = FileSystems.getDefault();
                Path       src = fs.getPath(exportKeyStore.getAbsolutePath());
                Path       dst = fs.getPath(exportKeyStore.getAbsolutePath()+".bck"+(new SimpleDateFormat("yyyyMMddHHmmssSSS")).format(Calendar.getInstance().getTime()));
                Files.copy(src, dst);
                //fs.close();
            }
            keyStore.setCertificateEntry(host, tmDec.certChain[0]);
            for (int i=1;i<tmDec.certChain.length;++i) {
                keyStore.setCertificateEntry(host+"-"+i, tmDec.certChain[i]);
            }
            FileOutputStream fos = new FileOutputStream(exportKeyStore);
            keyStore.store(fos, storePass.toCharArray());
            fos.close();
            System.out.println("Certificate added");
        } catch (Throwable t) {
            t.printStackTrace(System.err);
            exitCode = 0 == exitCode ? 3 : exitCode;
        }
    }

    private static class X509TrustManagerDecorator implements X509TrustManager {
        private X509TrustManager decorated;
        private X509Certificate  certChain[];

        private X509TrustManagerDecorator(X509TrustManager trustMgr) {
            if (null==trustMgr) {
                throw new NullPointerException("Trust manager cannot be null");
            }
            decorated = trustMgr;
            certChain = null;
        }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            decorated.checkClientTrusted(chain, authType);
        }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            certChain = chain;
            decorated.checkServerTrusted(chain, authType);
        }
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return decorated.getAcceptedIssuers();
        }
    }

    private void parseHost(String host_) {
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
        exitCode = 1;
        throw new IllegalArgumentException("Invalid host '"+host+"'");
    }

    private void processKeystore(String keyStore) throws IOException {
        File f = new File(keyStore);
        if (!f.exists()) {
            exitCode = 1;
            throw new FileNotFoundException("File/Directory '"+keyStore+"' does not exist");
        }
        if (f.isDirectory()) {
            f = new File(f, storeName);
            if (!f.exists()) {
                exitCode = 1;
                throw new FileNotFoundException("File '"+f+"' does not exist");
            }
            if (!f.isFile()) {
                exitCode = 1;
                throw new FileNotFoundException("File '"+f+"' is not a file!");
            }
            storePath = keyStore;
            return;
        }
        if (f.isFile()) {
            File d = f.getParentFile();
            if (null==d) {
                exitCode = 1;
                throw new IOException("Something went wrong null parent for '"+f+"'");
            }
            if (!d.exists()) {
                exitCode = 1;
                throw new IOException("Something went wrong parrent doesn't exist for '"+f+"'");
            }
            if (!d.isDirectory()) {
                exitCode = 1;
                throw new IOException("Something went wrong parrent not a directory for '"+f+"'");
            }
            storePath = d.getAbsolutePath();
            storeName = f.getName();
            return;
        }
        exitCode = 1;
        throw new IllegalArgumentException("Bad keyStore argument '"+keyStore+"'");
    }

    private static void printUsage() {
        System.out.println("java SSLImport [--host <fqdn_or_ip>] "+
                           "[--port <port num>] "+
                           "[--keystore <keystore path>] "+
                           "[--keystorepass <keystore password>] "+
                           "[--exportlocal] "+
                           "[--localstorename <local key store>]");
        System.out.println("java SSLImport --help");
        System.out.println("java SSLImport --version");
    }

    private void parseArgs(String[] args) throws IOException {
        for (int i=0;i<args.length;++i) {
            if ("--help".equals(args[i])) {
                printUsage();
                System.exit(0);
                continue;
            }
            if ("--version".equals(args[i])) {
                SSLImporterVersion.printVersion();
                System.exit(0);
                continue;
            }
            if ("--host".equals(args[i])) {
                if (args.length<i+2) {
                    System.err.println("Missing argument for --host ("+i+")!");
                    exitCode = 1;
                    throw new IllegalArgumentException();
                }
                ++i;
                parseHost(args[i]);
                continue;
            }
            if ("--port".equals(args[i])) {
                if (args.length<i+2) {
                    System.err.println("Missing argument for --port ("+i+")!");
                    exitCode = 1;
                    throw new IllegalArgumentException();
                }
                ++i;
                port = Integer.parseInt(args[i]);
                continue;
            }
            if ("--keystore".equals(args[i])) {
                if (args.length<i+2) {
                    System.err.println("Missing argument for --keystore ("+i+")!");
                    exitCode = 1;
                    throw new IllegalArgumentException();
                }
                ++i;
                processKeystore(args[i]);
                continue;
            }
            if ("--keystorepass".equals(args[i])) {
                if (args.length<i+2) {
                    System.err.println("Missing argument for --keystorepass ("+i+")!");
                    exitCode = 1;
                    throw new IllegalArgumentException();
                }
                ++i;
                storePass = args[i];
                continue;
            }
            if ("--exportlocal".equals(args[i])) {
                localExport = true;
                continue;
            }
            if ("--localstorename".equals(args[i])) {
                if (args.length<i+2) {
                    System.err.println("Missing argument for --localstorename ("+i+")!");
                    exitCode = 1;
                    throw new IllegalArgumentException();
                }
                ++i;
                localStore = args[i];
                continue;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        SSLImport ssli = new SSLImport();
        ssli.parseArgs(args);
        ssli.run();
        if (0!=ssli.exitCode) {
            System.exit(ssli.exitCode);
        }
    }
}


