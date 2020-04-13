package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.BashCommand;

public class ScanS3 implements ScanTask {
    private final String processedSubdomainsFilename;
    private final String potentialS3Buckets = "potential-s3-buckets-subdomains";

    public ScanS3(final String processedSubdomainsFilename) {
        this.processedSubdomainsFilename = processedSubdomainsFilename;
    }

    @Override
    public void run() {
        // put subdomains looking like potential s3 domains in a file to scan
        new BashCommand().runCommandOutputString(
                "rg  '(s3|bucket|aws)' " + processedSubdomainsFilename + " >> " + potentialS3Buckets);
        // scan potential buckets
        new BashCommand().runCommandOutputString(
                "python S3Scanner/s3scanner.py --include-closed --out-file found_s3_buckets.txt --list " +
                potentialS3Buckets);
    }
}
