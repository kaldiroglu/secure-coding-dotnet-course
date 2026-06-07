using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace dev.kaldiroglu.SecureCoding.Shop.Fixed.Controllers;

[ApiController]
[Route("import")]
public class ImportController : ControllerBase
{
    public record ImportDto(string Name);

    // FIXED: deserialize into a known DTO with default settings — "$type" is ignored, no type confusion.
    [HttpPost("json")]
    public IActionResult Json([FromBody] System.Text.Json.JsonElement raw)
    {
        JsonConvert.DeserializeObject<ImportDto>(raw.GetRawText());
        return Ok();
    }

    // FIXED: prohibit DTDs and disable the external resolver (this is also the .NET 8 default).
    [HttpPost("xml")]
    public async Task<IActionResult> Xml()
    {
        using var sr = new StreamReader(Request.Body);
        var body = await sr.ReadToEndAsync();
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new StringReader(body), settings);
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(reader);
            return Ok(doc.DocumentElement?.InnerText);
        }
        catch (XmlException)
        {
            return BadRequest("DTD / external entities are not allowed.");
        }
    }
}
