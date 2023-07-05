using System.Security.Cryptography.X509Certificates;
using AzureADClientAssertion;
using JWT.Algorithms;
using JWT.Builder;

namespace AzureADClientAssertion_Tests;

[TestClass]
public class ClientAssertion_Tests
{
    private X509Certificate2? signingCertificate;
    private string? tenantId;
    private string? clientId;

    [TestInitialize]
    public void Setup()
    {
        signingCertificate = new X509Certificate2("testcert.pfx", "", X509KeyStorageFlags.Exportable);
        tenantId = Guid.NewGuid().ToString();
        clientId = Guid.NewGuid().ToString();   
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentNullException))]
    public void Try_Instantiating_With_No_Certificate_Throws_Argument_Null_Exception()
    {
        var clientAssertion = new AzureADClientAssertionBuilder(null);
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Try_Creating_Assertion_With_Empty_Tenant_Id_Throws_Argument_Null_Exception()
    {
        var cert = new X509Certificate2("", "");
        var clientAssertion = new AzureADClientAssertionBuilder(cert);
        clientAssertion.CreateClientAssertion("", Guid.NewGuid().ToString());
    }

    [TestMethod]
    [ExpectedException(typeof(ArgumentException))]
    public void Try_Creating_Assertion_With_Empty_Client_Id_Throws_Argument_Null_Exception()
    {
        var cert = new X509Certificate2("", "");
        var clientAssertion = new AzureADClientAssertionBuilder(cert);
        clientAssertion.CreateClientAssertion(Guid.NewGuid().ToString(""),"");
    }

    [TestMethod]
    public void Try_Creating_Assertion_With_Correct_Parameters_Should_Return_Valid_Client_Assertion()
    {
        var clientAssertion = new AzureADClientAssertionBuilder(signingCertificate);
        var assertion = clientAssertion.CreateClientAssertion(tenantId, clientId);
        
        Assert.IsNotNull(assertion);
    }

    [TestMethod]
    public void Try_Creating_Assertion_Should_Verify_Aud_Value()
    {

        var expectedAudience = $"https://login.microsoftonline.com/{tenantId.ToString()}/oauth2/token";
        var clientAssertion = new AzureADClientAssertionBuilder(signingCertificate);
        var token = clientAssertion.CreateClientAssertion(tenantId, clientId);

        var payload = JwtBuilder.Create()
                        .WithAlgorithm(new RS256Algorithm(signingCertificate))
                        .MustVerifySignature()
                        .Decode<IDictionary<string, object>>(token);

        Assert.AreEqual(expectedAudience, payload["aud"].ToString());      
    }

    [TestMethod]
    public void Try_Creating_Assertion_Should_Verify_CertHash_In_Header_Is_Correct()
    {
        var expectedHash = AzureADClientAssertion.AzureADClientAssertionBuilder.Base64UrlEncode(signingCertificate?.GetCertHash());
        
        var clientAssertion = new AzureADClientAssertionBuilder(signingCertificate);
        var token = clientAssertion.CreateClientAssertion(tenantId, clientId);

        var payload = JwtBuilder.Create()
                        .WithAlgorithm(new RS256Algorithm(signingCertificate))
                        .MustVerifySignature()
                        .DecodeHeader<IDictionary<string, object>>(token);

        Assert.AreEqual(expectedHash, payload["x5t"].ToString());      
    }
}
