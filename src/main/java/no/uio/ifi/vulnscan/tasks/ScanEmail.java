package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.util.BashCommand;
import no.uio.ifi.vulnscan.util.io.FileParser;

public class ScanEmail implements ScanTask {
    private final String actualHostsToScanFileName;
    private final String emailResultFolderName;
    private final String simplyEmailPath;

    public ScanEmail(final String actualHostsToScanFileName,
                     final String emailResultFolderName,
                     final String simplyEmailPath) {
        this.actualHostsToScanFileName = actualHostsToScanFileName;
        this.emailResultFolderName = emailResultFolderName;
        this.simplyEmailPath = simplyEmailPath;
    }

    @Override
    public void run() {
        //1. Open a buffered stream from the list of hosts to scan
        final var hostnames = new FileParser().parseFile(actualHostsToScanFileName);
        //2. scan for email addresses
        hostnames.forEachOrdered(host ->
                                         new BashCommand().runCommandOutputString(
                                                 "source " + simplyEmailPath + "/SE/bin/activate && " +
                                                 "SimplyEmail.py -all -v -e " + host + " --json " +
                                                 host + "_emails.txt"
                                         )
        );
        hostnames.close();
        //3. move all email-results to a folder
        new BashCommand().runCommandOutputString(
                "mkdir -p " + emailResultFolderName + " && mv *_emails.txt " + emailResultFolderName
        );
    }
}
