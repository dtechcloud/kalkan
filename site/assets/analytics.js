/* Visit counts for the kalkan website, on the production site only.
 *
 * The deploy workflow (.github/workflows/site.yml) puts the Azure Application Insights
 * connection string in place of the placeholder below, for the production deploy only. A local
 * copy, a fork and the staging site keep the placeholder, so this file then does nothing.
 *
 * No cookies and no browser storage: the SDK counts page views, pages, countries, browsers
 * and referrers. Application Insights does not keep the client IP address.
 */
(function () {
  "use strict";
  var connection = "__KALKAN_INSIGHTS_CONNECTION_STRING__";
  if (connection.indexOf("InstrumentationKey=") !== 0) {
    return;
  }
  var script = document.createElement("script");
  // Application Insights JavaScript SDK 3.4.5 (MIT, Microsoft), pinned with a hash.
  script.src = "https://js.monitor.azure.com/scripts/b/ai.3.4.5.gbl.min.js";
  script.integrity = "sha384-aTKCfGVKAFg+If03Hanf/RLpTadzuv1kyXFITdZe/xx2AW3KxVHNVKRTjUz40hVh";
  script.crossOrigin = "anonymous";
  script.onload = function () {
    var ns = window.Microsoft && (window.Microsoft.ApplicationInsights3 || window.Microsoft.ApplicationInsights);
    if (!ns || !ns.ApplicationInsights) {
      return;
    }
    var insights = new ns.ApplicationInsights({
      config: {
        connectionString: connection,
        disableCookiesUsage: true,
        isStorageUseDisabled: true,
        disableAjaxTracking: true,
        disableFetchTracking: true,
        enableAutoRouteTracking: false
      }
    });
    insights.loadAppInsights();
    insights.trackPageView();
  };
  document.head.appendChild(script);
})();
