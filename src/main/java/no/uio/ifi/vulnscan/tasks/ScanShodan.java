package no.uio.ifi.vulnscan.tasks;

import com.fooock.shodan.ShodanRestApi;
import com.fooock.shodan.model.banner.Banner;
import com.fooock.shodan.model.host.FacetReport;
import com.fooock.shodan.model.host.HostReport;
import io.reactivex.observers.DisposableObserver;
import no.uio.ifi.vulnscan.util.io.FileOverWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class ScanShodan implements ScanTask {
    private static final Logger log = LoggerFactory.getLogger(ScanShodan.class);
    private final String shodanApiKey;
    private final String searchQueries;

    public ScanShodan(final String shodanApiKey, final String searchQueries) {
        this.shodanApiKey = shodanApiKey;
        this.searchQueries = searchQueries;
    }

    @Override
    public void run() {
        log.info("Starting Shodan-scan");
        final ShodanRestApi api = new ShodanRestApi(shodanApiKey);
        final ArrayList<String> results = new ArrayList<>();

        for (final var searchQuery : searchQueries.split(",")) {
            api.hostSearch(searchQuery)
               .subscribe(new DisposableObserver<HostReport>() {
                   @Override
                   public void onComplete() {
                       // called when the request is completed
                       log.info("shodan request completed.");
                   }

                   @Override
                   public void onError(final Throwable e) {
                       // called if an error occurs
                       log.error("An error occurred", e);
                   }

                   @Override
                   public void onNext(final HostReport hostReport) {
                       // result of the query
                       final int total = hostReport.getTotal();
                       final List<Banner> banners = hostReport.getBanners();
                       final FacetReport facet = hostReport.getFacet();
                       log.info(hostReport.toString());

                       results.add("Hosts found in total: " + total);
                       banners.forEach(b -> results.add(b.toString()));
                   }
               });
        }

        new FileOverWriter().writeContentsToFile(results, "shodan_results");
        log.info("Finished Shodan-scan");
    }
}
