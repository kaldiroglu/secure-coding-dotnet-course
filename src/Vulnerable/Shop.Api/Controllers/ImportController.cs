using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace dev.kaldiroglu.SecureCoding.Shop.Vulnerable.Controllers;

[ApiController]
[Route("import")]
public class ImportController : ControllerBase
{
    // CWE-502: TypeNameHandling.All lets the payload pick which .NET type to instantiate.
    // Bind the raw JSON via System.Text.Json, then re-deserialize with the vulnerable Newtonsoft settings.
    [HttpPost("json")]
    public IActionResult Json([FromBody] System.Text.Json.JsonElement raw)
    {
        JsonConvert.DeserializeObject(raw.GetRawText(),
            new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
        return Ok();
    }

    // CWE-611: XML parser with DTD processing and an external resolver enabled.
    [HttpPost("xml")]
    public async Task<IActionResult> Xml()
    {
        using var sr = new StreamReader(Request.Body);
        var body = await sr.ReadToEndAsync();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
        using var reader = XmlReader.Create(new StringReader(body), settings);
        var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        doc.Load(reader);
        return Ok(doc.DocumentElement?.InnerText);
    }
}
