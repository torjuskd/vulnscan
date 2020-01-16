package no.uio.ifi.vulnscan;

import org.apache.commons.io.input.ReversedLinesFileReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;

/**
 * A simple non-intrusive large scale vulnerability scanner
 */
public class VulnScan {
    private static final Logger log = LoggerFactory.getLogger(VulnScan.class);
    private static final String processedHostsFilename = "processed_hosts";
    private static final String subdomainsSubjackResultsFile = "subdomain_subjack_results";
    private static final String subdomainsTempFileName = "subdomains_temp";
    private static final String hostsToScanDefaultHostnameFilename = "hostnames";
    private static final String heartbleedFilename = "heartbleed_script_output";

    /**
     * @param filename       the path of the file containing the hosts you want to scan
     * @param isContinueMode if true: continue from previous scans, else start from beginning
     */
    public static void run(final String filename, final boolean isContinueMode) {

        //1. parse file line by line or in entirety
        var hostnames = new FileParser().parseFile(filename);

        if (isContinueMode) {
            log.info("Continuing previously started scan");
            final var lastHost = getLastHostnameFromPreviousSession();

            //Drop until last hostname from previous session, then skip that one too.
            hostnames = hostnames.dropWhile(host -> !host.equals(lastHost)).skip(1);
        }

        //TODO: check if this is set on the next login
        log.debug(new BashCommand().runCommandOutputString("echo $PATH"));

        log.info("Scan starting, processing domains:");
        //2. find subdomains (Subdomain enumeration using certificate transparency logs)
        hostnames.forEachOrdered(host -> {
                                     log.info(host);
                                     final ArrayList<String> subdomains = getSubdomains(host);

                                     checkForDomainTakeoverVulns(subdomains);

//                                     final var spaceDelimitedSubdomains = new StringBuilder();
//                                     subdomains.forEach(s -> spaceDelimitedSubdomains.append(s).append(" "));
//                                     spaceDelimitedSubdomains.deleteCharAt(spaceDelimitedSubdomains.length() - 1);
//                                     final var heartbleedOutput = new BashCommand().runCommandOutputString(
//                                             "nmap -sV -p 433 --host-timeout 5 --script-timeout 120 --script=ssl-heartbleed.nse "
//                                             + spaceDelimitedSubdomains + " >> " + heartbleedFilename);

                                     //x. Append processed hosts to file to keep track
                                     writeHostnameToProcessedFile(host);
                                 }
        );
        hostnames.close();
        log.info("All hosts processed, Finished.");

        //TODO ideas:
        //exposed credentials
        //exposed source code
        //other
        //* aws - open s3 buckets
        //* CORS misconfiguration
        //masscan -> nmap port, heartbleed -> sslscrape -> dangling cnames -> google -> github -> dirbuster -> subdomain discovery (eg. knockpy) ->

        // log progress to terminal domain by domain
        // Maybe save progress
    }

    private static String getLastHostnameFromPreviousSession() {
        try (final var reversedLinesFileReader =
                     new ReversedLinesFileReader(new File(processedHostsFilename), Charset.defaultCharset())) {
            return reversedLinesFileReader.readLine();
        } catch (final IOException e) {
            log.error("An error occurred while reading from " + processedHostsFilename, e);
            System.exit(0);
        }
        return null;
    }

    private static void checkForDomainTakeoverVulns(final ArrayList<String> subdomains) {
        // Write to file to use subjack
        new FileOverWriter().writeContentsToFile(subdomains, subdomainsTempFileName);

        // Subjack appends to result-file, so we don't have to change filename for repeated calls
        //TODO: fix PATH here
        final var subjackResults = new BashCommand()
                .runCommandOutPutArrayList(
                        "export PATH=\"$PATH:/home/torjusd/go/bin\"\n" +
                        "CURRENTDIR=$(pwd)\n" +
                        "subjack -w " +
                        "$CURRENTDIR/" + subdomainsTempFileName + " -t 100 -timeout 30 " +
                        "-o " + "$CURRENTDIR/" + subdomainsSubjackResultsFile + " -ssl -a");
    }

    private static void writeHostnameToProcessedFile(final String host) {
        try (final BufferedWriter writer = new BufferedWriter(
                new FileWriter(processedHostsFilename, true))) {
            writer.append(host).append("\n");
        } catch (final IOException e) {
            log.error("An error occurred while writing to processed hosts file \"{}\"", processedHostsFilename, e);
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
