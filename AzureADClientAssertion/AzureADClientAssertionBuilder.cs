namespace AzureADClientAssertion;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;


public class AzureADClientAssertionBuilder
{
    private readonly X509Certificate2 certificate;
    public AzureADClientAssertionBuilder(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        this.certificate = certificate;
    }
    public string CreateClientAssertion( string tenantId, string clientId)
    {
        if (string.IsNullOrEmpty(tenantId))
        {
            throw new ArgumentException($"'{nameof(tenantId)}' cannot be null or empty.", nameof(tenantId));
        }

        if (string.IsNullOrEmpty(clientId))
        {
            throw new ArgumentException($"'{nameof(clientId)}' cannot be null or empty.", nameof(clientId));
        }

        var rsa = certificate.GetRSAPrivateKey();

        //alg represents the desired signing algorithm, which is SHA-256 in this case
        //x5t represents the certificate thumbprint base64 url encoded
        var header = new Dictionary<string, string>()
            {
                { "alg", "RS256"},
                { "typ", "JWT" },
                { "x5t", Base64UrlEncode(certificate.GetCertHash()) }
            };

        //Please see the previous code snippet on how to craft claims for the GetClaims() method
        var claims = GetClaims(tenantId, clientId);

        var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);
        var claimsBytes = JsonSerializer.SerializeToUtf8Bytes(claims);
        string token = Base64UrlEncode(headerBytes) + "." + Base64UrlEncode(claimsBytes);

        string signature = Base64UrlEncode(rsa.SignData(Encoding.UTF8.GetBytes(token), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        string signedClientAssertion = string.Concat(token, ".", signature);
        return signedClientAssertion;
    }

    private IDictionary<string, object> GetClaims(string? tenantId, string? clientId)
    {
        string aud = $"https://login.microsoftonline.com/{tenantId}/oauth2/token";

        string? ConfidentialClientID = clientId; //client id 00000000-0000-0000-0000-000000000000
        const uint JwtToAadLifetimeInSeconds = 60 * 10; // Ten minutes
        DateTimeOffset validFrom = DateTimeOffset.UtcNow;
        DateTimeOffset validUntil = validFrom.AddSeconds(JwtToAadLifetimeInSeconds);
   
        return new Dictionary<string, object>()
            {
                { "aud", aud },
                { "exp", validUntil.ToUnixTimeSeconds() },
                { "iss", ConfidentialClientID ?? "unknown client id"},
                { "jti", Guid.NewGuid().ToString() },
                { "nbf", validFrom.ToUnixTimeSeconds() },
                { "sub", ConfidentialClientID ?? "unknown client id"}
            };
    }

    public static string Base64UrlEncode(byte[] arg)
    {
        char Base64PadCharacter = '=';
        char Base64Character62 = '+';
        char Base64Character63 = '/';
        char Base64UrlCharacter62 = '-';
        char Base64UrlCharacter63 = '_';

        string encodedPayload = Convert.ToBase64String(arg);
        encodedPayload = encodedPayload.Split(Base64PadCharacter)[0]; // RemoveAccount any trailing padding
        encodedPayload = encodedPayload.Replace(Base64Character62, Base64UrlCharacter62); // 62nd char of encoding
        encodedPayload = encodedPayload.Replace(Base64Character63, Base64UrlCharacter63); // 63rd char of encoding

        return encodedPayload;
    }
}
