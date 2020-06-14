package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.util.BashCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScanForEnvFiles implements ScanTask {
    private static final Logger log = LoggerFactory.getLogger(ScanForEnvFiles.class);
    final String megPathsFilename;
    private final String actualHostsToScanFileName;
    private final String megHostnamesWithProtocolFilename;

    public ScanForEnvFiles(final String megPathsFilename,
                           final String actualHostsToScanFileName,
                           final String megHostnamesWithProtocolFilename) {
        this.megPathsFilename = megPathsFilename;
        this.actualHostsToScanFileName = actualHostsToScanFileName;
        this.megHostnamesWithProtocolFilename = megHostnamesWithProtocolFilename;
    }

    @Override
    public void run() {

        log.info("running meg to look for files in webroot");

        new BashCommand().runCommandOutputString("sed -e 's/^/https:\\/\\//' " +
                                                 actualHostsToScanFileName + " > " +
                                                 megHostnamesWithProtocolFilename);
        // create paths file with /.env if it does not exist
        new BashCommand().runCommandOutputString(
                "[ ! -f " + megPathsFilename + " ] && echo \"/.env\" >> " + megPathsFilename);

        new BashCommand().runCommandOutputString(
                "meg --savestatus 200 " + megPathsFilename + " " +
                megHostnamesWithProtocolFilename);

        log.info("meg finished");
    }
}
