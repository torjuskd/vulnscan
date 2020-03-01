package no.uio.ifi.vulnscan;

/**
 * A simple non-intrusive large scale vulnerability scanner
 */
public final class Application {

    /**
     * @param args the path of the file containing the hosts you want to scan, and various other options
     */
    public static void main(final String[] args) {

        final VulnScan vulnScan = new VulnScan(args);
        vulnScan.run();
    }
}
