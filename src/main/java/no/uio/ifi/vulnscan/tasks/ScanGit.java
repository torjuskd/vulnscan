package no.uio.ifi.vulnscan.tasks;

import no.uio.ifi.vulnscan.BashCommand;

public class ScanGit implements ScanTask {
    final String hostnamesFile;

    public ScanGit(final String hostnamesFile) {this.hostnamesFile = hostnamesFile;}

    @Override
    public void run() {
        new BashCommand().runCommandOutputString("GitTools/Finder/gitfinder.py -i " + hostnamesFile + " -o git_repo_urls_found");
    }
}
