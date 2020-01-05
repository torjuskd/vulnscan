package no.uio.ifi.vulnscan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

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

        //1. parse file line by line or in entirety
        final var hostnames = new FileParser().parseFile(filename);

        //2. find subdomains (Subdomain enumeration using certificate transparency logs)
        hostnames.forEachOrdered(host -> {
                                     final ArrayList<String> subdomains = getSubdomains(host);

                                     //TODO: check if this is set on the next login
                                     new BashCommand().runCommandOutputString("echo $PATH");

                                     checkForDomainTakeoverVulns(subdomains);

                                     //x. Append processed hosts to file to keep track
                                     writeHostnameToProcessedFile(host);
                                 }
        );
        hostnames.close();

        //TODO ideas:
        //4. run nmap with safe scripts
        //exposed credentials
        //exposed source code
        //other
        //* aws - open s3 buckets
        //* CORS misconfiguration
        //masscan -> nmap port, heartbleed -> sslscrape -> dangling cnames -> google -> github -> dirbuster -> subdomain discovery (feks. knockpy) ->

        // log progress to terminal domain by domain
        // Maybe save progress
    }

    private static void checkForDomainTakeoverVulns(final ArrayList<String> subdomains) {
        // Write to file to use subjack
        final String subdomainsTempFileName = "subdomains_temp";
        new FileOverWriter().writeContentsToFile(subdomains, subdomainsTempFileName);

        // Subjack appends to result-file, so we don't have to change filename for repeated calls
        //TODO: fix PATH here
        final String subdomainsSubjackResultsFile = "subdomain_subjack_results";
        final var subjackResults = new BashCommand()
                .runCommandOutPutArrayList(
                        "export PATH=\"$PATH:/home/torjusd/go/bin\"\n" +
                        "CURRENTDIR=$(pwd)\n" +
//                                                     "cd /home/torjusd/go\n" +
//                                                     "/home/torjusd/go/bin/subjack -w " +
                        "subjack -w " +
                        "$CURRENTDIR/" + subdomainsTempFileName + " -t 100 -timeout 30 " +
                        "-o " + "$CURRENTDIR/" + subdomainsSubjackResultsFile + " -ssl -a -v");
    }

    private static void writeHostnameToProcessedFile(final String host) {
        final String processedHostFilename = "processed_hosts";
        try (final BufferedWriter writer = new BufferedWriter(
                new FileWriter(processedHostFilename, true))) {
            writer.append(host).append("\n");
        } catch (final IOException e) {
            log.error("An error occurred while writing to processed hosts file \"{}\"", processedHostFilename, e);
        }
    }

    private static ArrayList<String> getSubdomains(final String host) {
        return new BashCommand()
                .runCommandOutPutArrayList("hostname=" + host + "\n" +
                                           "query=\"SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci " +
                                           "WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.$hostname'));\"\n" +
                                           "\n" +
                                           "(echo $hostname; echo $query | \\\n" +
                                           "    psql -t -h crt.sh -p 5432 -U guest certwatch | \\\n" +
                                           "    sed -e 's:^ *::g' -e 's:^*\\.::g' -e '/^$/d' | \\\n" +
                                           "    sed -e 's:*.::g';) | sort -u");
    }
}
