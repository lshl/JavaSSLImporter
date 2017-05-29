package org.lshl;


import java.io.BufferedWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * A version of the library.
 *
 * Created 5 Feb 2017
 */
public final class SSLImporterVersion {
    public static final String LIB_NAME       = "SSLImporter";
    public static final String LIB_DESCRPT    = "Java SSL certificate importer";
    public static final int    MAJOR          = 1;
    public static final int    MINOR          = 0;
    public static final int    BUILD_NUMBER   = 3;
    public static final String VERSION        = ""+MAJOR+"."+MINOR+"."+BUILD_NUMBER;
    public static final Date   BUILD_DATE     = new Date(1496036696127L);
    public static final String BUILD_DATE_STR = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z (EEE, dd MMM yyyy)").format(BUILD_DATE);

    /**
     * Non-instantiable class.
     */
    private SSLImporterVersion() {throw new UnsupportedOperationException();}

    public static String fullVersionStr() {
        @SuppressWarnings("resource")
        StringWriter sw = new StringWriter();
        @SuppressWarnings("resource")
        BufferedWriter bw = new BufferedWriter(sw);
        try {
            bw.write(LIB_NAME);       bw.newLine();
            bw.write(LIB_DESCRPT);    bw.newLine();
            bw.write(VERSION);        bw.newLine();
            bw.write(BUILD_DATE_STR);
            bw.close();
            sw.close();
        } catch (IOException e) {
            throw new RuntimeException("This was not supposed to happen!", e);
        }
        return sw.toString();
    }

    public static void printVersion() {
        System.out.println(fullVersionStr());
    }

    public static void main(String[] args) {
        printVersion();
    }
}
