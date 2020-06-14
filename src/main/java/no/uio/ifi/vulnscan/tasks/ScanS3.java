package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.util.BashCommand;

public class ScanS3 implements ScanTask {
    private final String processedSubdomainsFilename;
    private final String potentialS3Buckets = "potential-s3-buckets-subdomains";
    private final String foundS3BucketsFilename = "found_s3_buckets.txt";
    private final String s3ScannerPath;

    public ScanS3(final String processedSubdomainsFilename,
                  final String s3ScannerPath) {
        this.processedSubdomainsFilename = processedSubdomainsFilename;
        this.s3ScannerPath = s3ScannerPath;
    }

    @Override
    public void run() {
        // put subdomains looking like potential s3 domains in a file to scan
        new BashCommand().runCommandOutputString(
                "rg  '(s3|bucket|aws)' " + processedSubdomainsFilename + " >> " + potentialS3Buckets);
        // scan potential buckets
        new BashCommand().runCommandOutputString(
                "python " + s3ScannerPath + "/s3scanner.py --include-closed --out-file " + foundS3BucketsFilename + " --list " +
                potentialS3Buckets);
    }
}
