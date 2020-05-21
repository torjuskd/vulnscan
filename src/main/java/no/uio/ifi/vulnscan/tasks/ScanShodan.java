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
import java.util.Properties;

public class ScanShodan implements ScanTask {
    private static final Logger log = LoggerFactory.getLogger(ScanShodan.class);
    private final Properties properties;

    public ScanShodan(final Properties properties) {
        this.properties = properties;
    }

    @Override
    public void run() {
        log.info("Starting Shodan-scan");
        final ShodanRestApi api = new ShodanRestApi(properties.getProperty("SHODAN_API_KEY"));
        final String shodanSearchQuery = properties.getProperty("SHODAN_SEARCH_QUERY");

        /*
         *
         * SHODAN_API_KEY = ""
         * query = "port:3389 org:hospital"
         * endpoint = "https://api.shodan.io/shodan/host/search?key="+SHODAN_API_KEY+"&query="+query+"&page="
         * cve = "CVE-2019-0708"
         * fresh = []
         */

        api.hostSearch(shodanSearchQuery)
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

                   final ArrayList<String> results = new ArrayList<>();
                   results.add("Hosts found in total: " + total);
                   banners.forEach(b -> results.add(b.toString()));

                   new FileOverWriter().writeContentsToFile(results, "shodan_results");
               }
           });

        log.info("Finished Shodan-scan");
    }
}
