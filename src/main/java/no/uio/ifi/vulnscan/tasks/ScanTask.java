package no.uio.ifi.vulnscan.tasks;

/**
 * ScanTask interface
 * <p>
 * This interface that the different tasks of the scanner has to implement.
 */
public interface ScanTask extends Runnable {
    void run();
}
