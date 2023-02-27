using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using System.Web;
using Org.BouncyCastle.Math;

namespace Satispay
{

    public class SatispayRequestSigningDelegatingHandler : DelegatingHandler
    {
        private readonly string _keyId;
        private readonly string _privateKey;

        public SatispayRequestSigningDelegatingHandler(
            string keyId,
            string privateKey,
            HttpMessageHandler innerHandler) : base(innerHandler)
        {
            _keyId = keyId;
            _privateKey = privateKey;
        }

        public SatispayRequestSigningDelegatingHandler(
            string keyId,
            string privateKey,
            bool createInnerHandler = false)
        {
            _keyId = keyId;
            _privateKey = privateKey;

            if (createInnerHandler)
                InnerHandler = new HttpClientHandler();
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            await AddDigestHeaderAsync(request);

            AddAuthorizationHeader(request);

            return await base.SendAsync(request, cancellationToken);
        }

        private static async Task AddDigestHeaderAsync(HttpRequestMessage request)
        {
            var body = request.Content != null
                ? await request.Content.ReadAsStringAsync()
                : string.Empty;

            using (var sha256 = SHA256.Create())
            {
                var hashed = sha256.ComputeHash(Encoding.UTF8.GetBytes(body));
                request.Headers.Add("Digest", $"SHA-256={Convert.ToBase64String(hashed)}");
            }
        }

        private void AddAuthorizationHeader(HttpRequestMessage request)
        {
            var @string = BuildStringToSign(request);
            var signature = SignData(@string);

            var header = $"keyId=\"{_keyId}\", algorithm=\"rsa-sha256\", headers=\"(request-target) host date digest\", signature=\"{Convert.ToBase64String(signature)}\"";
            request.Headers.Authorization = new AuthenticationHeaderValue("Signature", header);
        }

        private byte[] SignData(string data)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(ImportPrivateKey(_privateKey));
                return rsa.SignData(Encoding.UTF8.GetBytes(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public static RSAParameters ImportPrivateKey(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            RsaPrivateCrtKeyParameters privKey = (RsaPrivateCrtKeyParameters)pr.ReadObject();
            RSAParameters rp = new RSAParameters();
            rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
            rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
            rp.P = privKey.P.ToByteArrayUnsigned();
            rp.Q = privKey.Q.ToByteArrayUnsigned();
            rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
            rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
            rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
            rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);


            return rp;
        }

        private static byte[] ConvertRSAParametersField(BigInteger n, int size)
        {
            byte[] bs = n.ToByteArrayUnsigned();
            if (bs.Length == size)
                return bs;
            if (bs.Length > size)
                throw new ArgumentException("Specified size too small", "size");
            byte[] padded = new byte[size];
            Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
            return padded;
        }

        private static string BuildStringToSign(HttpRequestMessage request)
            => new StringBuilder()
                .AppendLine($"(request-target): {request.Method.ToString().ToLowerInvariant()} {request.RequestUri.PathAndQuery}")
                .AppendLine($"host: {request.RequestUri.Host}")
                .AppendLine($"date: {request.Headers.Date?.UtcDateTime:ddd, dd MMM yyyy HH:mm:ss z}")
                .Append($"digest: {request.Headers.GetValues("Digest").Single()}")
                .ToString();
    }




    public partial class Default : System.Web.UI.Page
    {
        private const string ApiUrl = "https://staging.authservices.satispay.com/g_business/";
        private const string SandboxApiUrl = "https://staging.authservices.satispay.com/g_business/";
        private HttpClient BuildClient(
            string keyId,
            string privateKey,
            bool production)
        {
            var requestSigningHandler = new SatispayRequestSigningDelegatingHandler(keyId, privateKey, true);

            return new HttpClient(requestSigningHandler)
            {
                BaseAddress = new Uri(production ? ApiUrl : SandboxApiUrl)
            };
        }

        internal class TestSignatureRequest
        {
            [JsonPropertyName("flow")]
            public string Flow { get; set; }
            [JsonPropertyName("amount_unit")]
            public int AmountUnit { get; set; }
            [JsonPropertyName("currency")]
            public string Currency { get; set; }
        }

        internal class AuthenticationResource
        {
            [JsonPropertyName("authentication_key")]
            public AuthenticationKeyResource AuthenticationKey { get; set; }
            [JsonPropertyName("signature")]
            public SignatureResource Signature { get; set; }
            [JsonPropertyName("signed_string")]
            public string SignedString { get; set; }

            public class AuthenticationKeyResource
            {
                [JsonPropertyName("access_key")]
                public string AccessKey { get; set; }
                [JsonPropertyName("customer_uid")]
                public string CustomerUid { get; set; }
                [JsonPropertyName("key_type")]
                public string KeyType { get; set; }
                [JsonPropertyName("auth_type")]
                public string AuthType { get; set; }
                [JsonPropertyName("role")]
                public string Role { get; set; }
                [JsonPropertyName("enable")]
                public bool Enable { get; set; }
                [JsonPropertyName("insert_date")]
                public DateTime InsertDate { get; set; }
                [JsonPropertyName("version")]
                public int Version { get; set; }
            }

            public class SignatureResource
            {
                [JsonPropertyName("key_id")]
                public string KeyId { get; set; }
                [JsonPropertyName("algorithm")]
                public string Algorithm { get; set; }
                [JsonPropertyName("headers")]
                public string[] Headers { get; set; }
                [JsonPropertyName("signature")]
                public string Signature { get; set; }
                [JsonPropertyName("resign_required")]
                public bool ResignRequired { get; set; }
                [JsonPropertyName("iteration_count")]
                public int IterationCount { get; set; }
                [JsonPropertyName("valid")]
                public bool Valid { get; set; }
            }
        }

        public class SatispayError
        {
            [JsonPropertyName("code")]
            public int Code { get; set; }
            [JsonPropertyName("message")]
            public string Message { get; set; }
        }

        private static async Task ThrowErrorIfAnyAsync(HttpResponseMessage response)
        {
            if (response.IsSuccessStatusCode)
                return;

            var body = await response.Content.ReadAsStringAsync();
            var error = JsonSerializer.Deserialize<SatispayError>(body);

           if (error != null)
                throw new Exception(" errore: "+response.StatusCode+" "+ error.Code+ " " + error.Message);
        }

        private static async Task<T> SendRequestAsync<T>(
            HttpClient httpClient,
            HttpMethod httpMethod,
            string requestUri,
            object requestBody,
            CancellationToken cancellationToken)
        {
            var request = new HttpRequestMessage(httpMethod, requestUri);
            if (requestBody != null)
                request.Content = new StringContent(JsonSerializer.Serialize(requestBody, new JsonSerializerOptions
                {
                    WriteIndented = true
                }), Encoding.UTF8, "application/json");
            var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            await ThrowErrorIfAnyAsync(response);

            var responseBody = await response.Content.ReadAsStringAsync();

            return responseBody?.Length > 0
                ? JsonSerializer.Deserialize<T>(responseBody)
                : default;
        }
        private Task<AuthenticationResource> TestAuthenticationAsync(
            string keyId,
            string privateKey,
            CancellationToken cancellationToken = default)
        {
            var httpClient = BuildClient(keyId, privateKey, false);

            return SendRequestAsync<AuthenticationResource>(
                httpClient, HttpMethod.Post, "/wally-services/protocol/tests/signature", new TestSignatureRequest
                {
                    Flow = "MATCH_CODE",
                    AmountUnit = 100,
                    Currency = "EUR"
                }, cancellationToken);
        }




        protected async Task Page_LoadAsync(object sender, EventArgs e)
        {
            string key_id = "mke3o60ri96gcb7dlmm17jct37kn4j7781i9h53b49584qucbnl4msg8f4rfqnki57om3v86l4ugj6qpr8cfok5bi8lt1tm6mnirqcct15tnggv9gcp2d7kk0g93u5m7h565gcpuati100ourih6prp9es2ns4s0kg67hkpkqql9pisa9103e09k9q1itgj6ulbpp345";
            //string staging_key_id = "tn95lce37u3e4q5hhbrdb50lh70iql22atd3nonr5qclhrpas044vhv23vl9rfngsi9tllvil29ns7vpc2jdn0oa4mvtg0223gba47flke0u1ace2q1v9mivbsm3be3pmd41rqaknv6t652e35k54p340kn6ek7d1l7r4dau4f0gmsd1d19gda5f36ioehkpgh5hbau9";


            // Load the private key from the PEM file
            string privateKeyFilePath = Server.MapPath("/pem/private.pem");
            string privateKeyPem = File.ReadAllText(privateKeyFilePath);

            var pemReader = new PemReader(new StringReader(privateKeyPem));
            var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;


            //string body = "{\"flow\":\"MATCH_CODE\",\"amount_unit\":100,\"currency\":\"EUR\"}";
            //string body = "{\n  \"flow\": \"MATCH_CODE\",\n  \"amount_unit\": 100,\n  \"currency\": \"EUR\"\n}";

            DateTime data = DateTime.Now;
            var date = data.ToString("ddd, d MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture) + " " + data.ToString("zzz").Replace(":", string.Empty);


            AuthenticationResource authenticationResource = await TestAuthenticationAsync(key_id, privateKey.ToString());
            //string digest;
            //using (SHA256 sha256 = SHA256.Create())
            //{
            //digest = $"SHA-256={Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(body)))}";
            //}

            //LiteralEsito.Text = digest;

            //Response.End();

            //StringBuilder sb = new StringBuilder(); ;
            //sb.AppendLine("(request-target): post /wally-services/protocol/tests/signature");
            //sb.AppendLine("host: staging.authservices.satispay.com");
            //sb.AppendLine("date: " + date);
            //sb.AppendLine("digest: " + digest);

            //string stringa = String.Format("(request-target): post /wally-services/protocol/tests/signature\n" +
            //    "host: staging.authservices.satispay.com\n" +
            //    "date: {0}\n" +
            //"digest: {1}", date, digest);

            //LiteralEsito.Text += "<p>stringa: " + sb.ToString() + "</p>";


            //string body = "{\"flow\":\"MATCH_CODE\",\"amount_unit\":100,\"currency\":\"EUR\"}";

            //string digest = "SHA-256=" + Convert.ToBase64String(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(body)));

            //LiteralEsito.Text += "<p>body: " + body + "</p>";

            //LiteralEsito.Text += "<p>digest: " + digest + "</p>";

            //string stringToSign = "(request-target): post /wally-services/protocol/tests/signature\n" +
            //    "host: staging.authservices.satispay.com\n" +
            //    "date: " + date + "\n" +
            //    "digest: " + digest;

           

            //// Compute the SHA-256 hash of the input string
            //var shaDigest = new Sha256Digest();
            //byte[] message = Encoding.UTF8.GetBytes(stringToSign);
            //shaDigest.BlockUpdate(message, 0, message.Length);
            //byte[] hash = new byte[shaDigest.GetDigestSize()];
            //shaDigest.DoFinal(hash, 0);

            ////// Create an RSA signer and initialize it with the private key and the SHA-256 digest
            //var signer = new RsaDigestSigner(new Sha256Digest());
            //signer.Init(true, privateKey);
            //signer.BlockUpdate(hash, 0, hash.Length);

            ////// Generate the signature and convert it to a Base64 string
            //byte[] signature = signer.GenerateSignature();
            //string base64Signature = Convert.ToBase64String(signature);

            //LiteralEsito.Text += "<p>stringToSign: " + stringToSign + "</p>";

            //LiteralEsito.Text += "<p>private key: " + privateKeyPem + "</p>";

            //LiteralEsito.Text += "<p>base64Signature: " + base64Signature + "</p>";


            // Create a PemReader and read the key
            //PemReader pemReader = new PemReader(new StringReader(privateKey));
            //RsaPrivateCrtKeyParameters rsaParams = (RsaPrivateCrtKeyParameters)pemReader.ReadObject();

            //// Convert the BouncyCastle RSA parameters to .NET RSA parameters
            //RSAParameters rsaParamsDotNet = new RSAParameters
            //{
            //    Modulus = rsaParams.Modulus.ToByteArrayUnsigned(),
            //    Exponent = rsaParams.PublicExponent.ToByteArrayUnsigned(),
            //    D = rsaParams.Exponent.ToByteArrayUnsigned(),
            //    P = rsaParams.P.ToByteArrayUnsigned(),
            //    Q = rsaParams.Q.ToByteArrayUnsigned(),
            //    DP = rsaParams.DP.ToByteArrayUnsigned(),
            //    DQ = rsaParams.DQ.ToByteArrayUnsigned(),
            //    InverseQ = rsaParams.QInv.ToByteArrayUnsigned()
            //};

            //// Create an RSACryptoServiceProvider and import the key
            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //rsa.ImportParameters(rsaParamsDotNet);

            //string inputString = stringToSign;

            //// Create a string to sign
            ////string message = "Hello, world!";

            //// Convert the string to bytes
            //byte[] data2 = Encoding.UTF8.GetBytes(stringToSign);

            //// Compute the signature using RSA-SHA256 algorithm
            //byte[] signature = rsa.SignData(data2, new SHA256CryptoServiceProvider());

            //// Convert the signature to Base64 format
            //string base64Signature = Convert.ToBase64String(signature);





            //using (var rsa = new RSACryptoServiceProvider())
            //{
            //    rsa.FromXmlString(private_key);
            //    byte[] signatureRaw = rsa.SignData(Encoding.UTF8.GetBytes(stringToSign), SHA256.Create());
            //    signature = Convert.ToBase64String(signatureRaw);
            //    Console.WriteLine(signature);
            //}


            //ASCIIEncoding ByteConverter = new ASCIIEncoding();
            //byte[] inputBytes = ByteConverter.GetBytes(sb.ToString());

            //byte[] inputHash = new SHA256CryptoServiceProvider().ComputeHash(inputBytes);

            //byte[] privateKeyBytes = Convert.FromBase64String(private_key
            //    .Replace("-----BEGIN RSA PRIVATE KEY-----", string.Empty)
            //    .Replace("-----END RSA PRIVATE KEY-----", string.Empty)
            //    .Replace("\n", string.Empty));

            //RSACryptoServiceProvider rsa = RSAUtils.DecodeRSAPrivateKey(privateKeyBytes);

            //byte[] output = rsa.SignHash(inputHash, "SHA256");

            //string signature = Convert.ToBase64String(output);


            //string authorizationHeader = string.Format("Signature keyId=\"{0}\", algorithm=\"rsa-sha256\", headers=\"(request-target)  host date digest\", signature=\"{1}\"", key_id, signature);

            //string url = @"https://staging.authservices.satispay.com/wally-services/protocol/tests/signature";
            //HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            //request.Method = "POST";
            //request.Host = "staging.authservices.satispay.com";
            //request.Date = data;
            ////request.PreAuthenticate= true;
            //request.ContentType = "application/json";
            ////request.Headers.Add("Date", date);
            //request.Headers.Add("Digest", digest);
            //request.Headers.Add("Authorization", authorizationHeader);

            //LiteralEsito.Text = "Date: " + date + "<br />" +
            //    "Digest: " + digest + "<br />" +
            //    "Authorization: " + authorizationHeader;

            // Get the response from the server
            //var response = (HttpWebResponse)request.GetResponse();
            //using (var streamReader = new StreamReader(response.GetResponseStream()))
            //{
            //    string responseString = streamReader.ReadToEnd();
            //}

            //var sign = GetSignature(private_key, signature);
        }
    }
}