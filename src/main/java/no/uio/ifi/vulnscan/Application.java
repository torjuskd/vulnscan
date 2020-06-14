package no.uio.ifi.vulnscan;

/**
 * A simple non-intrusive large scale vulnerability scanner
 */
public final class Application {

    /**
     */
    public static void main(final String[] args) {

        final VulnScanController vulnScanController = new VulnScanController();
        vulnScanController.run();
    }
}
