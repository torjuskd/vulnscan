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

public class ScanGoogle implements ScanTask {
    private static final Logger log = LoggerFactory.getLogger(ScanGoogle.class);
    private final String apikey;
    private final String searchQueries;
    private final String cx;

    public ScanGoogle(final String apikey, final String searchQueries, final String cx) {
        this.apikey = apikey;
        this.searchQueries = searchQueries;
        this.cx = cx;
    }

    @Override
    public void run() {
        log.info("Starting Google-scan");
        try {

            final Customsearch cs = new Customsearch.Builder(GoogleNetHttpTransport.newTrustedTransport(),
                                                             JacksonFactory.getDefaultInstance(),
                                                             null)
                    .setApplicationName("MyApplication")
                    .setGoogleClientRequestInitializer(new CustomsearchRequestInitializer(apikey))
                    .build();
            final ArrayList<String> results = new ArrayList<>();

            for (final var searchQuery : searchQueries.split(",")) {

                final Customsearch.Cse.List list = cs.cse().list(searchQuery).setCx(cx);
                final Search searchResult = list.execute();
                log.info("Total number of google-hits: " + searchResult.getSearchInformation().getTotalResults());

                if (searchResult.getItems() == null) {
                    continue;
                }

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
