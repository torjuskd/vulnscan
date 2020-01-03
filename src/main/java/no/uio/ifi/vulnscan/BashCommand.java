package no.uio.ifi.vulnscan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class BashCommand {

    final Logger log = LoggerFactory.getLogger(getClass());

    public String runCommand(final String command) {

        log.info("running command " + "\"" + command + "\"");
        final ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", command);

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
                log.info(output.toString());
                return output.toString();
            } else {
                log.error(output.toString());
                log.error("Received non-zero (faulty) exit code " + exitVal);
            }
        } catch (final IOException | InterruptedException e) {
            log.error("An error occurred " + e);
        }
        return "";
    }
}
