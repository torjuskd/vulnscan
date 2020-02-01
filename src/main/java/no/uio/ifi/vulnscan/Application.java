package no.uio.ifi.vulnscan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * A simple non-intrusive large scale vulnerability scanner
 */
public final class Application {
    private static final Logger log = LoggerFactory.getLogger(Application.class);
    private static final String hostsToScanDefaultHostnameFilename = "hostnames";

    /**
     * @param args the path of the file containing the hosts you want to scan
     */
    public static void main(final String[] args) {

        // handle input file or use default "hostnames"-file
        final String filename;
        if (args.length > 0 && args[0] != null && !args[0].isBlank() && new File(args[0]).isFile()) {
            filename = args[0];
        } else {
            filename = hostsToScanDefaultHostnameFilename;
            if (!new File(hostsToScanDefaultHostnameFilename).isFile()) {
                log.error("Run application using:\n" +
                          "java -jar vulnscan [fileWithHostNames] [--continue/-c, --aggressive/-a]");
                System.exit(0);
            }
        }

        // run scanner
        VulnScan.run(filename, isContinueMode(args), isAggressiveMode(args));
    }

    private static boolean isAggressiveMode(final String[] args) {
        for (final String argument : args) {
            if (argument.equalsIgnoreCase("--aggressive") || argument.equalsIgnoreCase("-a")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isContinueMode(final String[] args) {
        for (final String argument : args) {
            if (argument.equalsIgnoreCase("--continue") || argument.equalsIgnoreCase("-c")) {
                return true;
            }
        }
        return false;
    }
}
