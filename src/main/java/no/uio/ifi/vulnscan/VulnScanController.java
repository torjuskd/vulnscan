package no.uio.ifi.vulnscan;

import no.uio.ifi.vulnscan.tasks.*;
import no.uio.ifi.vulnscan.util.io.FileParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * The "controller"-class of non-intrusive large scale vulnerability scanner
 * Handles properties, constants and the execution of all the tasks of the scanner
 */
public class VulnScanController {
    private final Logger log = LoggerFactory.getLogger(VulnScanController.class);
    private final String processedHostsFilename = "processed_hosts";
    private final String processedSubdomainsFilename = "processed_subdomains";
    private final String subdomainsSubjackResultsFile = "subdomain_subjack_results";
    private final String subdomainsTempFileName = "subdomains_temp";
    private final String heartbleedFilename = "heartbleed_script_output";
    private final String megPathsFilename = "meg_paths";
    private final String emailResultFolderName = "email_output";
    private final String propertiesFileName = "vulnscan.config";
    private final String megHostnamesWithProtocolFilename = "meg_hostnames_with_protocol";
    private final String simplyEmailDir;
    private final String hostsToScan;
    private final String googleApiKey;
    private final String googleSearchQuery;
    private final String googleSearchEngine;
    private final String shodanApiKey;
    private final String shodanSearchQuery;
    private final String s3ScannerPath;
    private final Properties properties;
    private final List<CompletableFuture<Void>> scanTasks;

    /**
     * Sets the following
     * filename       the path of the file containing the hosts you want to scan
     *
     */
    public VulnScanController() {
        scanTasks = new ArrayList<>();

        properties = FileParser.readProperties(propertiesFileName);

        hostsToScan = properties.getProperty("HOST_LIST_TO_SCAN_FILENAME");
        simplyEmailDir = properties.getProperty("SIMPLY_EMAIL_DIR");
        googleApiKey = properties.getProperty("GOOGLE_API_KEY");
        googleSearchQuery = properties.getProperty("GOOGLE_SEARCH_QUERY");
        googleSearchEngine = properties.getProperty("GOOGLE_SEARCH_ENGINE");
        shodanApiKey = properties.getProperty("SHODAN_API_KEY");
        shodanSearchQuery = properties.getProperty("SHODAN_SEARCH_QUERY");
        s3ScannerPath =  properties.getProperty("S3_SCANNER_DIR");
    }

    /**
     * Run the various tasks of the scanner
     * <p>
     * This is where scan tasks are executed. Add new scan tasks here if wanted.
     * New scan tasks have to implement the ScanTask-interface, see {@link ScanTask}.
     * <p>
     * Tasks can run in parallel or sequentially. This is accomplished
     * through the use of CompletableFutures.
     */
    public void run() {
        if (taskShouldRun(ScanForEnvFiles.class)) {
            addTaskToPipeline(new ScanForEnvFiles(megPathsFilename,
                                                  hostsToScan,
                                                  megHostnamesWithProtocolFilename));
        }

        if (taskShouldRun(ScanGit.class)) {
            addTaskToPipeline(new ScanGit(hostsToScan));
        }

        /*
         * Only runs s3 scan after subdomain enumeration.
         */
        if (taskShouldRun(ScanSubdomains.class) && taskShouldRun(ScanS3.class)) {
            scanTasks.add(CompletableFuture.runAsync(
                    new ScanSubdomains(new FileParser().parseFile(hostsToScan),
                                       subdomainsTempFileName,
                                       subdomainsSubjackResultsFile,
                                       processedHostsFilename,
                                       processedSubdomainsFilename))
                                           .thenRun(new ScanS3(processedSubdomainsFilename,
                                                               s3ScannerPath)));
        } else if (taskShouldRun(ScanSubdomains.class)) {
            addTaskToPipeline(new ScanSubdomains(new FileParser().parseFile(hostsToScan),
                                                 subdomainsTempFileName,
                                                 subdomainsSubjackResultsFile,
                                                 processedHostsFilename,
                                                 processedSubdomainsFilename));
        }

        if (taskShouldRun(ScanHeartbleed.class)) {
            addTaskToPipeline(new ScanHeartbleed(hostsToScan,
                                                 heartbleedFilename));
        }

        if (taskShouldRun(ScanEmail.class)) {
            addTaskToPipeline(new ScanEmail(hostsToScan,
                                            emailResultFolderName,
                                            simplyEmailDir));
        }

        if (taskShouldRun(ScanShodan.class)) {
            addTaskToPipeline(new ScanShodan(shodanApiKey,
                                             shodanSearchQuery));
        }

        if (taskShouldRun(ScanGoogle.class)) {
            addTaskToPipeline(new ScanGoogle(googleApiKey,
                                             googleSearchQuery,
                                             googleSearchEngine));
        }

        log.info("Scan starting, processing domains.");
        scanTasks.forEach(CompletableFuture::join);
        log.info("All hosts processed, Finished.");
    }

    /**
     * Checks if a task should be run, based on parameters in the config-file.
     * classname=true to run a task or
     * classname=false to not run a task
     *
     * @param clazz the class of the scan-task
     * @return true if task should run
     */
    private boolean taskShouldRun(final Class clazz) {
        return Boolean.parseBoolean(properties.getProperty(clazz.getSimpleName()));
    }

    /**
     * Adds task to pipeline.
     * All the tasks that are added this way will be executed in parallel.
     *
     * @param runnable task to run
     */
    private void addTaskToPipeline(final Runnable runnable) {
        scanTasks.add(CompletableFuture.runAsync(runnable));
    }
}
