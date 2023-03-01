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
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using System.Web;
using Org.BouncyCastle.Math;
using System.Runtime.CompilerServices;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using System.Net;

namespace Satispay
{
    public enum Flow
    {
        MATCH_CODE,
        MATCH_USER,
        REFUND,
        PRE_AUTHORIZED
    }
    public enum PaymentType
    {
        TO_BUSINESS,
        REFUND_TO_BUSINESS
    }
    public enum Status
    {
        PENDING,
        ACCEPTED,
        CANCELED
    }
    public enum ActorType
    {
        CONSUMER,
        SHOP
    }

    public enum UpdateAction
    {
        ACCEPT,
        CANCEL,
        CANCEL_OR_REFUND
    }

    public class CreatePaymentRequest<T>
    {
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public Flow flow { get; set; }
        public int amount_unit { get; set; }

        //For PRE_AUTHORIZED Flow
        public string pre_authorized_payments_token { get; set; }

        //For REFUND Flow
        public string parent_payment_uid { get; set; }
        public string currency { get; set; } = "EUR";

        [JsonConverter(typeof(SatispayDateTimeConverter))]
        public DateTime? expiration_date { get; set; }

        //Order ID or payment external identifier
        public string external_code { get; set; }

        //https://myServer.com/myCallbackUrl?payment_id={uuid}
        public string callback_url { get; set; }

        //For MATCH_CODE Flow
        //https://myServer.com/myRedirectUrl
        public string redirect_url { get; set; }
        public T metadata { get; set; }

        //For MATCH_USER Flow
        public string consumer_uid { get; set; }
    }


    public class Sender
    {
        public string id { get; set; }

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ActorType type { get; set; } = ActorType.CONSUMER;
        public string name { get; set; }
    }

    public class Receiver
    {
        public string id { get; set; }

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public ActorType type { get; set; } = ActorType.SHOP;
    }

    public class PaymentResponse<T>
    {
        public string id { get; set; }

        //QR Code
        public string code_identifier { get; set; }

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public PaymentType type { get; set; }
        public int amount_unit { get; set; }
        public string currency { get; set; } = "EUR";

        [JsonConverter(typeof(JsonStringEnumConverter))]
        public Status status { get; set; }
        public bool expired { get; set; }

        //Metadata inserted within the payment request
        public T metadata { get; set; }
        public Sender sender { get; set; }
        public Receiver receiver { get; set; }

        [JsonConverter(typeof(SatispayDateTimeConverter))]
        public DateTime? insert_date { get; set; }

        [JsonConverter(typeof(SatispayDateTimeConverter))]
        public DateTime? expire_date { get; set; }

        //Order ID or payment external identifier
        public string external_code { get; set; }

        //https://online.satispay.com/pay/41da7b74-a9f4-4d25-8428-0e3e460d90c1?redirect_url=https%3A%2F%2FmyServer.com%2FmyRedirectUrl
        public string redirect_url { get; set; }
    }

    public class CreatePaymentResponse<T> : PaymentResponse<T>
    {
        public string QrCodeUrl { get; set; }
    }

    public class SatispayDateTimeConverter : JsonConverter<DateTime?>
    {
        private static readonly string _format = "yyyy-MM-ddTHH:mm:ss.fffZ";
        public override DateTime? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            return DateTime.ParseExact(reader.GetString(), _format, System.Globalization.CultureInfo.InvariantCulture);
        }

        public override void Write(Utf8JsonWriter writer, DateTime? value, JsonSerializerOptions options)
        {
            if (value.HasValue)
                writer.WriteStringValue(value.Value.ToUniversalTime().ToString(_format));
            else
                writer.WriteNullValue();
        }
    }
    public class RequestKeyIdRequest
    {
        public string public_key { get; set; }

        public string token { get; set; }
    }

    public class RequestKeyIdResponse
    {
        public string key_id { get; set; }
    }

    public class DailyClosure
    {
        public string id { get; set; }

        [JsonConverter(typeof(SatispayDateTimeConverter))]
        public DateTime? date { get; set; }
    }

    public class PaymentDetailsResponse<T> : PaymentResponse<T>
    {
        public DailyClosure daily_closure { get; set; }
    }

    public class UpdatePaymentRequest<T>
    {
        [JsonConverter(typeof(JsonStringEnumConverter))]
        public UpdateAction action { get; set; }
        public T metadata { get; set; }
    }

    public class Api
    {
        private const string baseDomain = "authservices.satispay.com";
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
        public string KeyId { get; set; }
        public string Version { get; private set; } = "1.2.0";
        public bool IsSandbox { get; private set; }

        private HttpClient httpClient;

        private AsymmetricCipherKeyPair ackp;

        public Api(HttpClient httpClient, bool isSandBox = false)
        {
            IsSandbox = isSandBox;
            this.httpClient = httpClient;
            httpClient.BaseAddress = isSandBox ?
            new Uri($"https://staging.{baseDomain}/g_business/v1/") :
            new Uri($"https://{baseDomain}/g_business/v1/");
        }

        public string GenerateRsaKeys()
        {
            RsaKeyPairGenerator rkpg = new RsaKeyPairGenerator();
            rkpg.Init(new KeyGenerationParameters(new SecureRandom(), 4096));
            ackp = rkpg.GenerateKeyPair();

            PublicKey = GetPem(ackp.Public);

            PrivateKey = GetPem(ackp.Private);

            return PrivateKey;
        }

        private string GetPem(AsymmetricKeyParameter akp)
        {
            StringBuilder keyPem = new StringBuilder();
            PemWriter pemWriter = new PemWriter(new StringWriter(keyPem));
            pemWriter.WriteObject(akp);
            pemWriter.Writer.Flush();

            return keyPem.ToString().Replace("\r", string.Empty);
        }

        public void SetAsymmetricKeyParameter(string pemPrivateKey)
        {
            var pemReader = new PemReader(new StringReader(pemPrivateKey));
            ackp = (AsymmetricCipherKeyPair)pemReader.ReadObject();
        }


       

        public async Task<string> RequestKeyId(RequestKeyIdRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.token))
                throw new ArgumentNullException("Missing activationToken argument");

            request.public_key = request.public_key ?? PublicKey;

            if (string.IsNullOrWhiteSpace(request.public_key))
                throw new ArgumentNullException("Missing PublicKey");

            HttpResponseMessage response = null;

            try
            {
                response = await httpClient.PostAsJsonAsync("authentication_keys", request);

                response.EnsureSuccessStatusCode();

                var result = await response.Content.ReadFromJsonAsync<RequestKeyIdResponse>();

                KeyId = result.key_id;

                return KeyId;
            }
            catch (HttpRequestException ex)
            {
                switch (response.StatusCode)
                {
                    //case HttpStatusCode.NotFound:
                    //    throw new ActivationTokenNotFoundException();
                    //case HttpStatusCode.Forbidden:
                    //    throw new ActivationTokenAlreadyPairedException();
                    //case HttpStatusCode.BadRequest:
                    //    throw new InvalidRsaKeyException();
                }

                throw ex;
            }
        }

        private async Task<T> SendJsonAsync<T>(HttpMethod method, string requestUri, object content = null, string idempotencyKey = null)
        {
            var requestJson = string.Empty;

            if (content != null)
                requestJson = JsonSerializer.Serialize(content, new JsonSerializerOptions()
                {
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                    WriteIndented = true
                });

            var httpRequestMessage = new HttpRequestMessage(method, requestUri)
            {
                Content = content == null ? null : new StringContent(requestJson, Encoding.UTF8, "application/json")
            };

            using (SHA256 sha256 = SHA256.Create())
            {
                var now = DateTime.Now;
                var date = now.ToString("ddd, d MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture) + " " + now.ToString("zzz").Replace(":", string.Empty);

                httpRequestMessage.Headers.Add("Date", date);

                var signature = new StringBuilder();

                signature.Append($"(request-target): {method.Method.ToLower()} {httpClient.BaseAddress.LocalPath}{requestUri}\n");
                signature.Append($"host: {httpClient.BaseAddress.Host}\n");
                signature.Append($"date: {((string[])httpRequestMessage.Headers.GetValues("Date"))[0]}\n");

                var digest = $"SHA-256={Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(requestJson)))}";

                signature.Append($"digest: {digest}");

                var sign = SignData(signature.ToString(), ackp.Private);

                httpRequestMessage.Headers.Add("Digest", digest);
                httpRequestMessage.Headers.Add("Authorization",
                    $"Signature keyId=\"{KeyId}\", algorithm=\"rsa-sha256\", headers=\"(request-target) host date digest\", signature=\"{sign}\"");

                if (idempotencyKey != null)
                    httpRequestMessage.Headers.Add("Idempotency-Key", idempotencyKey);

                httpRequestMessage.Headers.Add("x-satispay-appn", "Satispay.NET");

                HttpResponseMessage response = null;

                string stringContent = string.Empty;

                
                    response = await httpClient.SendAsync(httpRequestMessage);

                    stringContent = await response.Content.ReadAsStringAsync();

                    response.EnsureSuccessStatusCode();

                    return JsonSerializer.Deserialize<T>(stringContent);
               
            }
        }

        private string SignData(string msg, AsymmetricKeyParameter privKey)
        {
            byte[] msgBytes = Encoding.UTF8.GetBytes(msg);

            ISigner signer = SignerUtilities.GetSigner("SHA256WithRSA");
            signer.Init(true, privKey);
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
            byte[] sigBytes = signer.GenerateSignature();

            return Convert.ToBase64String(sigBytes);
        }

        private bool VerifySignature(AsymmetricKeyParameter pubKey, string signature, string msg)
        {
            byte[] msgBytes = Encoding.UTF8.GetBytes(msg);
            byte[] sigBytes = Convert.FromBase64String(signature);

            ISigner signer = SignerUtilities.GetSigner("SHA256WithRSA");
            signer.Init(false, pubKey);
            signer.BlockUpdate(msgBytes, 0, msgBytes.Length);
            return signer.VerifySignature(sigBytes);
        }

        


        public async Task<CreatePaymentResponse<T>> CreatePayment<T>(CreatePaymentRequest<T> request, string idempotencyKey = null)
        {
           

            var response = await SendJsonAsync<CreatePaymentResponse<T>>(HttpMethod.Post, "payments", request, idempotencyKey);

            //TODO
            response.QrCodeUrl = IsSandbox ? $"https://staging.online.satispay.com/qrcode/{response.code_identifier}" : $"https://online.satispay.com/qrcode/{response.code_identifier}";

            return response;
        }
        public async Task<PaymentDetailsResponse<T>> GetPaymentDetails<T>(string paymentId)
        {
            return await SendJsonAsync<PaymentDetailsResponse<T>>(HttpMethod.Get, $"payments/{paymentId}");
        }
        public async Task<PaymentDetailsResponse<T>> UpdatePaymentDetails<T>(string paymentId, UpdatePaymentRequest<T> request)
        {
            return await SendJsonAsync<PaymentDetailsResponse<T>>(HttpMethod.Put, $"payments/{paymentId}", request);
        }
    }






    public partial class Default : System.Web.UI.Page
    {


        private async Task callSatispayAuthentication(string privateKey)
        {
            HttpClient client = new HttpClient();

            Api api = new Api(client, true);
            api.PrivateKey=privateKey;
            api.SetAsymmetricKeyParameter(privateKey);
            var pRequest = new Satispay.CreatePaymentRequest<string>();

            //string body = "{\"flow\":\"MATCH_CODE\",\"amount_unit\":100,\"currency\":\"EUR\"}";

            pRequest.amount_unit = 100;
            pRequest.currency = "EUR";
            pRequest.flow = Flow.MATCH_CODE;
            var pResponse = await api.CreatePayment(pRequest,null);
        }



        protected  void Page_Load(object sender, EventArgs e)
        {
            //string key_id = "mke3o60ri96gcb7dlmm17jct37kn4j7781i9h53b49584qucbnl4msg8f4rfqnki57om3v86l4ugj6qpr8cfok5bi8lt1tm6mnirqcct15tnggv9gcp2d7kk0g93u5m7h565gcpuati100ourih6prp9es2ns4s0kg67hkpkqql9pisa9103e09k9q1itgj6ulbpp345";
            //string staging_key_id = "tn95lce37u3e4q5hhbrdb50lh70iql22atd3nonr5qclhrpas044vhv23vl9rfngsi9tllvil29ns7vpc2jdn0oa4mvtg0223gba47flke0u1ace2q1v9mivbsm3be3pmd41rqaknv6t652e35k54p340kn6ek7d1l7r4dau4f0gmsd1d19gda5f36ioehkpgh5hbau9";


            // Load the private key from the PEM file
            string privateKeyFilePath = Server.MapPath("/pem/private.pem");
            string privateKeyPem = File.ReadAllText(privateKeyFilePath);

            //var pemReader = new PemReader(new StringReader(privateKeyPem));
            //var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            //var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;


            //string body = "{\"flow\":\"MATCH_CODE\",\"amount_unit\":100,\"currency\":\"EUR\"}";
            //string body = "{\n  \"flow\": \"MATCH_CODE\",\n  \"amount_unit\": 100,\n  \"currency\": \"EUR\"\n}";

            //DateTime data = DateTime.Now;
            //var date = data.ToString("ddd, d MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture) + " " + data.ToString("zzz").Replace(":", string.Empty);

            RegisterAsyncTask(new System.Web.UI.PageAsyncTask(()=>callSatispayAuthentication(privateKeyPem)));
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