package no.uio.ifi.vulnscan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

public class BashCommand {

    private static final Logger log = LoggerFactory.getLogger(BashCommand.class);


    public ArrayList<String> runCommandOutPutArrayList(final String command) {

        log.debug("running command " + "\"" + command + "\"");
        final ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", command);

        final ArrayList<String> output = new ArrayList<>();

        try {
            final Process process = processBuilder.start();
            final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            final BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.add(line);
                log.debug(output.toString());
            }

            final int exitVal = process.waitFor();
            if (exitVal != 0) {
                final StringBuilder errorOutput = new StringBuilder();
                String errorLine;
                while ((errorLine = errorReader.readLine()) != null) {
                    errorOutput.append(errorLine).append("\n");
                }
                log.error(errorOutput.toString());
                log.error("Received non-zero (faulty) exit code " + exitVal);
            }
        } catch (final IOException | InterruptedException e) {
            log.error("An error occurred " + e);
        }
        return output;
    }

    public String runCommandOutputString(final String command) {

        log.debug("running command " + "\"" + command + "\"");
        final ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", command);
        final StringBuilder output = new StringBuilder();

        try {
            final Process process = processBuilder.start();
            final BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            final BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
                log.debug(output.toString());
            }

            final int exitVal = process.waitFor();
            if (exitVal != 0) {
                final StringBuilder errorOutput = new StringBuilder();
                String errorLine;
                while ((errorLine = errorReader.readLine()) != null) {
                    errorOutput.append(errorLine).append("\n");
                }
                log.error(errorOutput.toString());
                log.error("Received non-zero (faulty) exit code " + exitVal);
            }
        } catch (final IOException | InterruptedException e) {
            log.error("An error occurred " + e);
        }
        return output.toString();
    }
}
