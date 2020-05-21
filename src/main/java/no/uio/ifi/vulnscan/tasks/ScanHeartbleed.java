package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.util.BashCommand;
import no.uio.ifi.vulnscan.util.io.FileParser;

public class ScanHeartbleed implements ScanTask {
    private final String actualHostsToScanFileName;
    private final String heartbleedFilename;

    public ScanHeartbleed(final String actualHostsToScanFileName, final String heartbleedFilename) {
        this.actualHostsToScanFileName = actualHostsToScanFileName;
        this.heartbleedFilename = heartbleedFilename;
    }

    @Override
    public void run() {
        //1. Open a buffered stream from the list of hosts to scan
        final var nmapHostnames = new FileParser().parseFile(actualHostsToScanFileName);
        nmapHostnames.forEachOrdered(host -> {

                                         // scan for heartbleed-vulnerability
                                         // time out for single hosts after two minutes
                                         // using default output format
                                         final var heartbleedOutput = new BashCommand().runCommandOutputString(
                                                 "nmap -p 443 --host-timeout 3m --script-timeout 900 --script=ssl-heartbleed "
                                                 + host + " >> " + heartbleedFilename);
                                     }
        );
        nmapHostnames.close();
    }
}
