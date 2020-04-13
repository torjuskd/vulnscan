package no.uio.ifi.vulnscan;

import no.uio.ifi.vulnscan.util.io.FileParser;
import no.uio.ifi.vulnscan.tasks.*;
import no.uio.ifi.vulnscan.util.BashCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * A simple non-intrusive large scale vulnerability scanner
 */
public class VulnScan {
    private static final Logger log = LoggerFactory.getLogger(VulnScan.class);
    private static final String processedHostsFilename = "processed_hosts";
    private static final String processedSubdomainsFilename = "processed_subdomains";
    private static final String subdomainsSubjackResultsFile = "subdomain_subjack_results";
    private static final String subdomainsTempFileName = "subdomains_temp";
    private static final String heartbleedFilename = "heartbleed_script_output";
    private static final String agressiveScanOutputFilename = "agressive_scan_output";
    private static final String hostsToScanDefaultHostnameFilename = "hostnames";
    private static final String megPathsFilename = "meg_paths";
    private static boolean aggressiveMode;
    private final String actualHostsToScanFileName;

    /**
     * Sets the following
     * filename       the path of the file containing the hosts you want to scan
     * isContinueMode if true: continue from previous scans, else start from beginning
     * aggressiveMode can be set to perform aggressive scans
     *
     * @param args input arguments from command line
     */
    public VulnScan(final String[] args) {

        // handle input file or use default "hostnames"-file
        if (args.length > 0 && args[0] != null && !args[0].isBlank() && new File(args[0]).isFile()) {
            actualHostsToScanFileName = args[0];
        } else {
            actualHostsToScanFileName = hostsToScanDefaultHostnameFilename;
            if (!new File(hostsToScanDefaultHostnameFilename).isFile()) {
                log.error("Run application using:\n" +
                          "java -jar vulnscan [fileWithHostNames] [--continue/-c, --aggressive/-a]");
                System.exit(0);
            }
        }

        for (final String argument : args) {
            if (argument.equalsIgnoreCase("--aggressive") || argument.equalsIgnoreCase("-a")) {
                aggressiveMode = true;
                break; // NB: remove break if more conditions are added
            }
        }
    }

    /**
     * Run the various tasks of the scanner
     * <p>
     * This is where scan tasks are executed. Add new scan tasks here if wanted.
     * New scan tasks have to implement the ScanTask-interface, see {@link ScanTask}.
     * Tasks can be done in parallel or sequentially. This is accomplished
     * through the use of CompletableFutures.
     */
    public void run() {
        log.debug("PATH: " + new BashCommand().runCommandOutputString("echo $PATH"));

        final List<CompletableFuture<Void>> scanTasks = new ArrayList<>();

        // RUN MEG
        scanTasks.add(CompletableFuture.runAsync(new ScanForEnvFiles(megPathsFilename, actualHostsToScanFileName)));

        // RUN git scan
        scanTasks.add(CompletableFuture.runAsync(new ScanGit(actualHostsToScanFileName)));

        // RUN subdomain scan
        // THEN run s3 scan after subdomains are looked up
        scanTasks.add(CompletableFuture.runAsync(new ScanSubdomains(new FileParser().parseFile(actualHostsToScanFileName),
                                                                    subdomainsTempFileName,
                                                                    subdomainsSubjackResultsFile,
                                                                    processedHostsFilename,
                                                                    processedSubdomainsFilename))
                                       .thenRun(new ScanS3(processedSubdomainsFilename)));

        // RUN heartbleed scan
        scanTasks.add(CompletableFuture.runAsync(new ScanHeartbleed(actualHostsToScanFileName, heartbleedFilename)));

        log.info("Scan starting, processing domains.");
        scanTasks.forEach(CompletableFuture::join);
        log.info("All hosts processed, Finished.");
    }
}
