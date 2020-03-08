package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.BashCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScanForEnvFiles extends ScanTask {
    private static final Logger log = LoggerFactory.getLogger(ScanForEnvFiles.class);
    final String megPathsFilename;
    private final String actualHostsToScanFileName;

    public ScanForEnvFiles(final String megPathsFilename, final String actualHostsToScanFileName) {
        this.megPathsFilename = megPathsFilename;
        this.actualHostsToScanFileName = actualHostsToScanFileName;
    }

    @Override
    public void run() {

        log.info("running meg to look for files in webroot");

        final var megHostnamesWithProtocolFilename = "meg_hostnames_with_protocol";
        new BashCommand().runCommandOutputString("sed -e 's/^/https:\\/\\//' " + actualHostsToScanFileName + " > " +
                                                 megHostnamesWithProtocolFilename);
        // create paths file with /.env if it does not exist
        new BashCommand().runCommandOutputString(
                "[ ! -f " + megPathsFilename + " ] && echo \"/.env\" >> " + megPathsFilename);

        new BashCommand().runCommandOutputString(
                "meg --savestatus 200 " + megPathsFilename + " " + megHostnamesWithProtocolFilename);

        log.info("meg finished");
    }
}
