package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.BashCommand;
import no.uio.ifi.vulnscan.io.FileParser;

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

                                         //3. scan for heartbleed-vulnerability
                                         // time out for single hosts after two minutes, (can change to give output in condensed greppable format)
                                         final var heartbleedOutput = new BashCommand().runCommandOutputString(
                                                 "nmap -p 443 --host-timeout 3m --script-timeout 900 --script=ssl-heartbleed "
                                                 + host + " >> " + heartbleedFilename);

//                                         //4. Perform a typical scan if in agressive mode, but also force OS-guessing
//                                         if (aggressiveMode) {
//                                             final var agressiveScanOutput = new BashCommand().runCommandOutputString(
//                                                     "sudo nmap -A -T4 --osscan-guess --host-timeout 5m" + host
//                                                     + " >> " + agressiveScanOutputFilename);
//                                         }

//                                     final var spaceDelimitedSubdomains = new StringBuilder();
//                                     subdomains.forEach(s -> spaceDelimitedSubdomains.append(s).append(" "));
//                                     spaceDelimitedSubdomains.deleteCharAt(spaceDelimitedSubdomains.length() - 1);
//                                     final var heartbleedOutput = new BashCommand().runCommandOutputString(
//                                             "nmap -sV -p 433 --host-timeout 5 --script-timeout 120 --script=ssl-heartbleed.nse "
//                                             + spaceDelimitedSubdomains + " >> " + heartbleedFilename);
                                     }
        );
        nmapHostnames.close();
    }
}
