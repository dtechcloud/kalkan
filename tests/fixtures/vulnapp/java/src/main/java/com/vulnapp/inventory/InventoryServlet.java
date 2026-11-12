package com.vulnapp.inventory;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

@WebServlet("/inventory/*")
public class InventoryServlet extends HttpServlet {
    private static final String DB_URL = System.getenv("VULNAPP_JDBC_URL");
    private static final Path REPORT_DIR = Paths.get(System.getenv("VULNAPP_DATA"), "reports");
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final ObjectInputFilter CART_FILTER =
            ObjectInputFilter.Config.createFilter("com.vulnapp.inventory.CartState;java.base/*;!*");
    private static final Map<String, String> RETURN_PAGES = Map.of("cart", "/cart", "orders", "/orders");
    private static final Map<String, String> STATUS_FEEDS = Map.of(
            "payments", "https://status.payments.vulnapp.internal/feed.json",
            "shipping", "https://status.shipping.vulnapp.internal/feed.json");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            switch (String.valueOf(request.getPathInfo())) {
                case "/search" -> searchItems(request, response);
                case "/filter" -> filterItems(request, response);
                case "/ping" -> pingHost(request, response);
                case "/ping/v2" -> pingHostV2(request, response);
                case "/report" -> downloadReport(request, response);
                case "/report/summary" -> downloadSummary(request, response);
                case "/fetch" -> fetchUrl(request, response);
                case "/feed" -> fetchFeed(request, response);
                case "/page" -> searchPage(request, response);
                case "/page/compact" -> searchPageCompact(request, response);
                case "/login/continue" -> continueLogin(request, response);
                case "/logout/continue" -> continueLogout(request, response);
                default -> response.sendError(HttpServletResponse.SC_NOT_FOUND);
            }
        } catch (SQLException | InterruptedException e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            switch (String.valueOf(request.getPathInfo())) {
                case "/cart/restore" -> restoreCart(request, response);
                case "/cart/load" -> loadCart(request, response);
                case "/import" -> importXml(request, response);
                case "/import/v2" -> importXmlV2(request, response);
                default -> response.sendError(HttpServletResponse.SC_NOT_FOUND);
            }
        } catch (ClassNotFoundException | ParserConfigurationException | SAXException e) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
        }
    }

    @Override
    protected void doOptions(HttpServletRequest request, HttpServletResponse response) {
        if (String.valueOf(request.getPathInfo()).startsWith("/partner/")) {
            allowPartnerOrigin(request, response);
        } else {
            allowStoreOrigin(request, response);
        }
    }

    private void writeNames(HttpServletResponse response, ResultSet rows) throws IOException, SQLException {
        response.setContentType("text/plain;charset=UTF-8");
        while (rows.next()) {
            response.getWriter().println(Html.escape(rows.getString("name")));
        }
    }

    void searchItems(HttpServletRequest request, HttpServletResponse response) throws IOException, SQLException {
        String name = request.getParameter("name");
        try (Connection conn = DriverManager.getConnection(DB_URL); Statement stmt = conn.createStatement()) {
            ResultSet rows = stmt.executeQuery("SELECT id, name FROM items WHERE name = '" + name + "'");
            writeNames(response, rows);
        }
    }

    void filterItems(HttpServletRequest request, HttpServletResponse response) throws IOException, SQLException {
        String name = request.getParameter("name");
        try (Connection conn = DriverManager.getConnection(DB_URL);
                PreparedStatement stmt = conn.prepareStatement("SELECT id, name FROM items WHERE name = ?")) {
            stmt.setString(1, name);
            writeNames(response, stmt.executeQuery());
        }
    }

    void pingHost(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String host = request.getParameter("host");
        Process process = new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();
        response.getWriter().println(process.waitFor() == 0 ? "reachable" : "unreachable");
    }

    void pingHostV2(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String host = request.getParameter("host");
        Process process = new ProcessBuilder("ping", "-c", "1", "--", host).start();
        response.getWriter().println(process.waitFor() == 0 ? "reachable" : "unreachable");
    }

    void downloadReport(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        byte[] body = Files.readAllBytes(REPORT_DIR.resolve(name));
        response.getOutputStream().write(body);
    }

    void downloadSummary(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        byte[] body = Files.readAllBytes(REPORT_DIR.resolve(Paths.get(name).getFileName()));
        response.getOutputStream().write(body);
    }

    void fetchUrl(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String target = request.getParameter("url");
        HttpRequest outbound = HttpRequest.newBuilder(URI.create(target)).build();
        HttpResponse<InputStream> upstream = HTTP.send(outbound, HttpResponse.BodyHandlers.ofInputStream());
        upstream.body().transferTo(response.getOutputStream());
    }

    void fetchFeed(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        String feed = request.getParameter("feed");
        HttpRequest outbound = HttpRequest.newBuilder(URI.create(STATUS_FEEDS.get(feed))).build();
        HttpResponse<InputStream> upstream = HTTP.send(outbound, HttpResponse.BodyHandlers.ofInputStream());
        upstream.body().transferTo(response.getOutputStream());
    }

    void searchPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getParameter("q");
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("<h2>Results for " + query + "</h2>");
    }

    void searchPageCompact(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getParameter("q");
        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write("<h2>Results for " + Html.escape(query) + "</h2>");
    }

    void continueLogin(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(request.getParameter("next"));
    }

    void continueLogout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.sendRedirect(RETURN_PAGES.getOrDefault(request.getParameter("page"), "/"));
    }

    void restoreCart(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {
            Object state = in.readObject();
            request.getSession().setAttribute("cart", state);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    void loadCart(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {
            in.setObjectInputFilter(CART_FILTER);
            Object cart = in.readObject();
            request.getSession().setAttribute("cart", cart);
        }
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    void importXml(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ParserConfigurationException, SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder parser = factory.newDocumentBuilder();
        Document doc = parser.parse(request.getInputStream());
        response.getWriter().println(Html.escape(doc.getDocumentElement().getTagName()));
    }

    void importXmlV2(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ParserConfigurationException, SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(request.getInputStream());
        response.getWriter().println(Html.escape(doc.getDocumentElement().getTagName()));
    }

    void allowPartnerOrigin(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"));
        response.setHeader("Access-Control-Allow-Credentials", "true");
    }

    void allowStoreOrigin(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader("Access-Control-Allow-Origin", "https://shop.vulnapp.internal");
        response.setHeader("Access-Control-Allow-Credentials", "true");
    }
}
