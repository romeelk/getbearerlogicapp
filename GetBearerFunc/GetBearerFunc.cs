using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Azure.Security.KeyVault.Certificates;
using Newtonsoft.Json;
using Azure.Identity;
using System.Security.Cryptography.X509Certificates;
using AzureADClientAssertion;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace GetBearerFunc
{
    public static class GetBearerFunc
    {
        [FunctionName("GetBearerFunc")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            var keyVaultUri = Environment.GetEnvironmentVariable("KeyVaulUrlUri");
            var tenantId = Environment.GetEnvironmentVariable("TenantId");
            var clientId = Environment.GetEnvironmentVariable("ClientId");

            log.LogInformation($"About to authenticate to KV: {keyVaultUri}.");

            var client = new CertificateClient(vaultUri: new Uri(keyVaultUri), credential: new DefaultAzureCredential());

            var certName = req.Query["certificate"];

            if (string.IsNullOrEmpty(certName))
            {
                var modelState = new ModelStateDictionary();
                modelState.AddModelError("certificate","Certificate name is required");
                return new BadRequestObjectResult(modelState);
            }
            try 
            {
                await client.GetCertificateAsync(certName);
            }
            catch (Azure.RequestFailedException failedCertRequest)
            {
                log.LogWarning($"Could not find requeted certificate {failedCertRequest}..");
                return new NotFoundObjectResult(new { error = $"There was no certifcate with the name {certName} found." });
            }
            
            var cert = await client.DownloadCertificateAsync(certName);
        
            log.LogInformation($"Successfully grabbed certificate {cert.Value.FriendlyName}");
            log.LogInformation($"Certificate will expire on {cert.Value.GetExpirationDateString()}");
            log.LogInformation($"Checking for private key: {cert.Value.HasPrivateKey}");
        
            var clientAssertion = new AzureADClientAssertionBuilder(cert.Value);
            
            var token = clientAssertion.CreateClientAssertion(tenantId, clientId);

            return new OkObjectResult(token);
        }
    }
}
