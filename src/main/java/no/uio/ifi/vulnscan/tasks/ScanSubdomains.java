package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.util.BashCommand;
import no.uio.ifi.vulnscan.util.io.FileOverWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.stream.Stream;

public class ScanSubdomains implements ScanTask {
    private static final Logger log = LoggerFactory.getLogger(ScanSubdomains.class);
    private final Stream<String> hostnames;
    private final String subdomainsTempFileName;
    private final String subdomainsSubjackResultsFile;
    private final String processedHostsFilename;
    private final String processedSubdomainsFilename;

    public ScanSubdomains(final Stream<String> hostnames,
                          final String subdomainsTempFileName,
                          final String subdomainsSubjackResultsFile,
                          final String processedHostsFilename,
                          final String processedSubdomainsFilename) {this.hostnames = hostnames;
        this.subdomainsTempFileName = subdomainsTempFileName;
        this.subdomainsSubjackResultsFile = subdomainsSubjackResultsFile;
        this.processedHostsFilename = processedHostsFilename;
        this.processedSubdomainsFilename = processedSubdomainsFilename;
    }


    private void checkForDomainTakeoverVulns(final ArrayList<String> subdomains) {
        // Write to file to use subjack
        new FileOverWriter().writeContentsToFile(subdomains, subdomainsTempFileName);

        // Subjack appends to result-file, so we don't have to change filename for repeated calls
        final var subjackResults = new BashCommand()
                .runCommandOutPutArrayList(
                        "CURRENTDIR=$(pwd)\n" +
                        "subjack -w " +
                        "$CURRENTDIR/" + subdomainsTempFileName + " -t 100 -timeout 30 " +
                        "-o " + "$CURRENTDIR/" + subdomainsSubjackResultsFile + " -ssl -a");
    }

    private void writeHostnameToProcessedFile(final String host) {
        try (final BufferedWriter writer = new BufferedWriter(
                new FileWriter(processedHostsFilename, true))) {
            writer.append(host).append("\n");
        } catch (final IOException e) {
            log.error("An error occurred while writing to processed hosts file \"{}\"", processedHostsFilename, e);
        }
    }

    private void writeSubdomainsToProcessedFile(final ArrayList<String> subdomains) {
        try (final BufferedWriter writer = new BufferedWriter(
                new FileWriter(processedSubdomainsFilename, true))) {
            for (final String s : subdomains) {
                writer.append(s).append("\n");
            }
        } catch (final IOException e) {
            log.error("An error occurred while writing to processed hosts file \"{}\"",
                      processedSubdomainsFilename,
                      e);
        }
    }

    private ArrayList<String> getSubdomains(final String host) {
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

    @Override
    public void run() {
        log.info("Looking up and scanning subdomains");
        hostnames.forEachOrdered(host -> {
                                     log.info(host);

                                     //2. find subdomains (Subdomain enumeration using certificate transparency logs)
                                     final ArrayList<String> subdomains = getSubdomains(host);
                                     checkForDomainTakeoverVulns(subdomains);

                                     // Save looked up subdomains
                                     writeSubdomainsToProcessedFile(subdomains);
                                     //x Append processed hosts to file to save progress
                                     writeHostnameToProcessedFile(host);
                                 }
        );
        hostnames.close();
    }
}
