package no.uio.ifi.vulnscan.util.io;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class FileParser {
    private static final Logger log = LoggerFactory.getLogger(FileParser.class);

    public Stream<String> parseFile(final String filename) {
        try {
            return Files.lines(Paths.get(filename), Charset.defaultCharset());
        } catch (final IOException e) {
            log.error("An error occurred while parsing file " + filename, e);
            System.exit(0);
        }
        return Stream.empty();
    }
}
