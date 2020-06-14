package no.uio.ifi.vulnscan.util.io;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
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

    public static Properties readProperties(final String propertiesFileName) {
        final Properties properties = new Properties();

        InputStream is = null;
        try {
            is = new FileInputStream(propertiesFileName);
        } catch (final FileNotFoundException e) {
            log.error("Error parsing config file " + propertiesFileName, e);
            System.exit(0);
        }
        try {
            properties.load(is);
        } catch (final IOException e) {
            log.error("Error parsing config file " + propertiesFileName, e);
            System.exit(0);
        }
        return properties;
    }
}
