package no.uio.ifi.vulnscan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * A simple non-intrusive large scale vulnerability scanner
 */
public class Application {

    /**
     * @param args the path of the file containing the hosts you want to scan
     */
    public static void main(final String[] args) {

        final Logger log = LoggerFactory.getLogger(Application.class);

        log.info("test log statement");

        final ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash",
                               "-c",
                               "while read in; do bash getsubdomain \"$in\" >> top-1m-subdomains; done < top-1m");

        try {

            final Process process = processBuilder.start();

            final StringBuilder output = new StringBuilder();

            final BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line + "\n");
            }

            final int exitVal = process.waitFor();
            if (exitVal == 0) {
                log.info("Success!");
                log.info(output.toString());
                System.exit(0);
            } else {
                log.error("Received non-zero (faulty) exit code " + exitVal);
            }
        } catch (final IOException e) {
            log.error("An error occurred " + e);
        } catch (final InterruptedException e) {
            log.error("An error occurred " + e);
        }
    }
}
