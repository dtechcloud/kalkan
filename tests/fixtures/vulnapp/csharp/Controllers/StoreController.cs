using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.Data.SqlClient;
using MongoDB.Bson;
using MongoDB.Driver;
using Newtonsoft.Json;
using RazorEngineCore;

namespace VulnApp.Controllers;

[ApiController]
[Route("store")]
public class StoreController : ControllerBase
{
    private const string NoteTemplate = "<p>Note for @Model.Name</p>";

    private static readonly string ReportDir = Path.Combine(AppContext.BaseDirectory, "reports");
    private static readonly Dictionary<string, string> Formulas = new()
    {
        ["net"] = "100 * 0.8",
        ["gross"] = "100 * 1.2",
    };
    private static readonly Dictionary<string, string> StatusFeeds = new()
    {
        ["payments"] = "https://status.payments.vulnapp.internal/feed.json",
        ["shipping"] = "https://status.shipping.vulnapp.internal/feed.json",
    };

    private readonly string _connectionString;
    private readonly HttpClient _http;
    private readonly IMongoCollection<BsonDocument> _reports;

    public StoreController(IConfiguration configuration, HttpClient http, IMongoDatabase mongo)
    {
        _connectionString = configuration.GetConnectionString("Store") ?? "";
        _http = http;
        _reports = mongo.GetCollection<BsonDocument>("reports");
    }

    private static List<string> ReadNames(SqlCommand cmd)
    {
        var names = new List<string>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            names.Add(reader.GetString(1));
        }
        return names;
    }

    [HttpGet("items/search")]
    public IActionResult SearchItems([FromQuery] string name)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        using var cmd = new SqlCommand("SELECT id, name FROM items WHERE name = '" + name + "'", conn);
        return Ok(ReadNames(cmd));
    }

    [HttpGet("items/filter")]
    public IActionResult FilterItems([FromQuery] string name)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();
        using var cmd = new SqlCommand("SELECT id, name FROM items WHERE name = @name", conn);
        cmd.Parameters.AddWithValue("@name", name);
        return Ok(ReadNames(cmd));
    }

    [HttpGet("tools/ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        using var process = Process.Start("/bin/sh", "-c \"ping -c 1 " + host + "\"");
        process.WaitForExit();
        return Ok(process.ExitCode == 0);
    }

    [HttpGet("tools/ping/v2")]
    public IActionResult PingV2([FromQuery] string host)
    {
        var start = new ProcessStartInfo("ping");
        start.ArgumentList.Add("-c");
        start.ArgumentList.Add("1");
        start.ArgumentList.Add("--");
        start.ArgumentList.Add(host);
        using var process = Process.Start(start)!;
        process.WaitForExit();
        return Ok(process.ExitCode == 0);
    }

    [HttpGet("tools/calc")]
    public async Task<IActionResult> Calc([FromQuery] string expr)
    {
        var result = await CSharpScript.EvaluateAsync<double>(expr);
        return Ok(result);
    }

    [HttpGet("tools/calc/v2")]
    public async Task<IActionResult> CalcV2([FromQuery] string formula)
    {
        if (!Formulas.TryGetValue(formula, out var source))
        {
            return NotFound();
        }
        var result = await CSharpScript.EvaluateAsync<double>(source);
        return Ok(result);
    }

    [HttpPost("notes/preview")]
    public async Task<IActionResult> Preview([FromForm] string template, [FromForm] string name)
    {
        var engine = new RazorEngine();
        var compiled = await engine.CompileAsync(template);
        return Content(compiled.Run(new { Name = name }), "text/plain");
    }

    [HttpPost("notes/preview/v2")]
    public async Task<IActionResult> PreviewV2([FromForm] string name)
    {
        var engine = new RazorEngine();
        var compiled = await engine.CompileAsync(NoteTemplate);
        return Content(compiled.Run(new { Name = name }), "text/plain");
    }

    [HttpGet("search")]
    public IActionResult SearchPage([FromQuery] string q)
    {
        return Content("<h2>Results for " + q + "</h2>", "text/html");
    }

    [HttpGet("search/compact")]
    public IActionResult SearchPageCompact([FromQuery] string q)
    {
        return Content("<h2>Results for " + HtmlEncoder.Default.Encode(q) + "</h2>", "text/html");
    }

    [HttpGet("tools/fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        var body = await _http.GetStringAsync(url);
        return Content(body, "application/json");
    }

    [HttpGet("tools/feed")]
    public async Task<IActionResult> Feed([FromQuery] string feed)
    {
        if (!StatusFeeds.TryGetValue(feed, out var target))
        {
            return NotFound();
        }
        var body = await _http.GetStringAsync(target);
        return Content(body, "application/json");
    }

    [HttpGet("reports")]
    public IActionResult Report([FromQuery] string name)
    {
        var bytes = System.IO.File.ReadAllBytes(Path.Combine(ReportDir, name));
        return File(bytes, "application/pdf");
    }

    [HttpGet("reports/summary")]
    public IActionResult ReportSummary([FromQuery] string name)
    {
        var bytes = System.IO.File.ReadAllBytes(Path.Combine(ReportDir, Path.GetFileName(name)));
        return File(bytes, "application/pdf");
    }

    [HttpGet("login/continue")]
    public IActionResult ContinueLogin([FromQuery] string returnUrl)
    {
        return Redirect(returnUrl);
    }

    [HttpGet("logout/continue")]
    public IActionResult ContinueLogout([FromQuery] string returnUrl)
    {
        return LocalRedirect(Url.IsLocalUrl(returnUrl) ? returnUrl : "/");
    }

    [HttpPost("cart/restore")]
    public IActionResult RestoreCart([FromBody] string state)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        var cart = JsonConvert.DeserializeObject(state, settings);
        return Ok(cart?.GetType().Name);
    }

    [HttpPost("cart/load")]
    public IActionResult LoadCart([FromBody] string state)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
        var cart = JsonConvert.DeserializeObject<Dictionary<string, int>>(state, settings);
        return Ok(cart?.Count);
    }

    [HttpPost("import")]
    public IActionResult Import([FromBody] string xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
        using var reader = XmlReader.Create(new StringReader(xml), settings);
        var doc = new XmlDocument();
        doc.Load(reader);
        return Ok(doc.DocumentElement?.Name);
    }

    [HttpPost("import/v2")]
    public IActionResult ImportV2([FromBody] string xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using var reader = XmlReader.Create(new StringReader(xml), settings);
        var doc = new XmlDocument();
        doc.Load(reader);
        return Ok(doc.DocumentElement?.Name);
    }

    [HttpPost("reports/search")]
    public IActionResult SearchReports([FromBody] string filter)
    {
        var docs = _reports.Find(BsonDocument.Parse(filter)).ToList();
        return Ok(docs.Count);
    }

    [HttpGet("reports/search/v2")]
    public IActionResult SearchReportsV2([FromQuery] string owner)
    {
        var docs = _reports.Find(Builders<BsonDocument>.Filter.Eq("owner", owner)).ToList();
        return Ok(docs.Count);
    }
}
