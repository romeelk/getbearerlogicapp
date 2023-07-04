using System.Security.Cryptography.X509Certificates;
using AzureADClientAssertion;

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

}