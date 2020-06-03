package no.uio.ifi.vulnscan.tasks;

import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.customsearch.Customsearch;
import com.google.api.services.customsearch.CustomsearchRequestInitializer;
import com.google.api.services.customsearch.model.Result;
import com.google.api.services.customsearch.model.Search;
import no.uio.ifi.vulnscan.util.io.FileOverWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Properties;

public class ScanGoogle implements ScanTask {
    private static final Logger log = LoggerFactory.getLogger(ScanGoogle.class);
    private final Properties properties;

    public ScanGoogle(final Properties properties) {
        this.properties = properties;
    }

    @Override
    public void run() {
        log.info("Starting Google-scan");
        try {

            final String searchQuery = properties.getProperty("GOOGLE_SEARCH_QUERY"); //The query to search
            final String cx = properties.getProperty("GOOGLE_SEARCH_ENGINE"); //The configured search engine
            final String apikey = properties.getProperty("GOOGLE_API_KEY");

            final Customsearch cs = new Customsearch.Builder(GoogleNetHttpTransport.newTrustedTransport(),
                                                             JacksonFactory.getDefaultInstance(),
                                                             null)
                    .setApplicationName("MyApplication")
                    .setGoogleClientRequestInitializer(new CustomsearchRequestInitializer(apikey))
                    .build();

            final Customsearch.Cse.List list = cs.cse().list(searchQuery).setCx(cx);

            final ArrayList<String> results = new ArrayList<>();

            final Search searchResult = list.execute();
            log.info("Total number of google-hits: " + searchResult.getSearchInformation().getTotalResults());

            if (searchResult.getItems() != null) {
                for (final Result resultItem : searchResult.getItems()) {
                    results.add(resultItem.getLink() + "," + resultItem.getTitle() + "," + resultItem.getSnippet());
                }
            }

            new FileOverWriter().writeContentsToFile(results, "google_results");
        } catch (final GeneralSecurityException | IOException e) {
            log.error("An error occurred running google search task", e);
        }
        log.info("Finished Google-scan");
    }
}
