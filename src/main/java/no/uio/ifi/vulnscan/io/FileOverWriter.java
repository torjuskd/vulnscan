package no.uio.ifi.vulnscan.io;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.ArrayList;

public class FileOverWriter {
    private static final Logger log = LoggerFactory.getLogger(FileOverWriter.class);

    public void writeContentsToFile(final ArrayList<String> contents, final String filename) {

        //overwrites file contents
        try (final BufferedWriter writer = new BufferedWriter(new java.io.FileWriter(filename, false))) {
            contents.forEach(l -> {
                try {
                    writer.append(l).append("\n");
                } catch (final IOException e) {
                    log.error("An error occurred while writing to file \"{}\"", filename, e);
                }
            });
        } catch (final IOException e) {
            log.error("An error occurred while writing to file \"{}\"", filename, e);
        }
    }
}
