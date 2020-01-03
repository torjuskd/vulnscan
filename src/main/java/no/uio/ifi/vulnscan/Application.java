package no.uio.ifi.vulnscan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * A simple non-intrusive large scale vulnerability scanner
 */
public final class Application {
    private static final Logger log = LoggerFactory.getLogger(Application.class);

    /**
     * @param args the path of the file containing the hosts you want to scan
     */
    public static void main(final String[] args) {

        // Handle input file or use default "hostnames"-file
        final String filename;
        if (args.length > 0 && args[0] != null && !args[0].isBlank() && new File(args[0]).isFile()) {
            filename = args[0];
        } else if (new File("hostnames").isFile()) {
            filename = "hostnames";
        } else {
            log.error("Run application using:\n" +
                      "java -jar vulnscan fileWithHostNames");
            System.exit(0);
            filename = "";
        }

        //TODO:
        //1. parse file line by line or in entirety
        final var hostnames = new FileParser().parseFile(filename);

        //2. find subdomains (Subdomain enumeration using certificate transparency logs)
        hostnames.forEachOrdered(host -> {
                                     getSubdomains(host);
                                 }
        );
        hostnames.close();
    }

    private static String getSubdomains(final String host) {
        return new BashCommand()
                .runCommand("hostname=" + host + "\n" +
                            "query=\"SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci " +
                            "WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.$hostname'));\"\n" +
                            "\n" +
                            "(echo $hostname; echo $query | \\\n" +
                            "    psql -t -h crt.sh -p 5432 -U guest certwatch | \\\n" +
                            "    sed -e 's:^ *::g' -e 's:^*\\.::g' -e '/^$/d' | \\\n" +
                            "    sed -e 's:*.::g';) | sort -u");
    }
}
