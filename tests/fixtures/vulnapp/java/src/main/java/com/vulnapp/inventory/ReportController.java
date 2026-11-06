package com.vulnapp.inventory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.model.Filters;
import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.bson.Document;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/reports")
public class ReportController {
    private static final Algorithm JWT_ALGORITHM = Algorithm.HMAC256(System.getenv("VULNAPP_JWT_KEY"));
    private static final Map<String, String> FORMULAS = Map.of("net", "100 * 0.8", "gross", "100 * 1.2");

    private final Configuration freemarker = new Configuration(Configuration.VERSION_2_3_34);
    private final ExpressionParser expressions = new SpelExpressionParser();
    private final MongoCollection<Document> reports =
            MongoClients.create(System.getenv("VULNAPP_MONGO_URL")).getDatabase("vulnapp").getCollection("reports");

    @PostMapping("/preview")
    public String preview(@RequestParam("template") String template, @RequestParam("title") String title)
            throws IOException, TemplateException {
        Template page = new Template("preview", new StringReader(template), freemarker);
        StringWriter out = new StringWriter();
        page.process(Map.of("title", title), out);
        return out.toString();
    }

    @PostMapping("/preview/v2")
    public String previewV2(@RequestParam("title") String title) throws IOException, TemplateException {
        Template page = freemarker.getTemplate("preview.ftl");
        StringWriter out = new StringWriter();
        page.process(Map.of("title", title), out);
        return out.toString();
    }

    @GetMapping("/price")
    public Object price(@RequestParam("expr") String expr) {
        return expressions.parseExpression(expr).getValue();
    }

    @GetMapping("/price/v2")
    public Object priceV2(@RequestParam("formula") String formula) {
        return expressions.parseExpression(FORMULAS.getOrDefault(formula, "0")).getValue();
    }

    @PostMapping("/search")
    public List<String> search(@RequestBody String filter) {
        List<String> titles = new ArrayList<>();
        reports.find(Document.parse(filter)).forEach(doc -> titles.add(doc.getString("title")));
        return titles;
    }

    @GetMapping("/search/v2")
    public List<String> searchV2(@RequestParam("owner") String owner) {
        List<String> titles = new ArrayList<>();
        reports.find(Filters.eq("owner", owner)).forEach(doc -> titles.add(doc.getString("title")));
        return titles;
    }

    @GetMapping("/mine")
    public String mine(@RequestHeader("Authorization") String authorization) {
        DecodedJWT token = JWT.decode(authorization.replace("Bearer ", ""));
        return token.getSubject();
    }

    @GetMapping("/mine/v2")
    public String mineV2(@RequestHeader("Authorization") String authorization) {
        DecodedJWT token = JWT.require(JWT_ALGORITHM).build().verify(authorization.replace("Bearer ", ""));
        return token.getSubject();
    }

    @CrossOrigin(originPatterns = "*", allowCredentials = "true")
    @GetMapping("/shared")
    public List<String> shared() {
        return List.of("weekly", "monthly");
    }

    @CrossOrigin(origins = "https://shop.vulnapp.internal", allowCredentials = "true")
    @GetMapping("/shared/v2")
    public List<String> sharedV2() {
        return List.of("weekly", "monthly");
    }
}
