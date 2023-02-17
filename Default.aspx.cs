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

namespace Satispay
{
    public partial class Default : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string key_id = "mke3o60ri96gcb7dlmm17jct37kn4j7781i9h53b49584qucbnl4msg8f4rfqnki57om3v86l4ugj6qpr8cfok5bi8lt1tm6mnirqcct15tnggv9gcp2d7kk0g93u5m7h565gcpuati100ourih6prp9es2ns4s0kg67hkpkqql9pisa9103e09k9q1itgj6ulbpp345";
            //string staging_key_id = "tn95lce37u3e4q5hhbrdb50lh70iql22atd3nonr5qclhrpas044vhv23vl9rfngsi9tllvil29ns7vpc2jdn0oa4mvtg0223gba47flke0u1ace2q1v9mivbsm3be3pmd41rqaknv6t652e35k54p340kn6ek7d1l7r4dau4f0gmsd1d19gda5f36ioehkpgh5hbau9";

            //string body = "{\"flow\":\"MATCH_CODE\",\"amount_unit\":100,\"currency\":\"EUR\"}";
            //string body = "{\n  \"flow\": \"MATCH_CODE\",\n  \"amount_unit\": 100,\n  \"currency\": \"EUR\"\n}";

            DateTime data = DateTime.Now;
            var date = data.ToString("ddd, d MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture) + " " + data.ToString("zzz").Replace(":", string.Empty);

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


            string body = "{\"flow\":\"MATCH_CODE\",\"amount_unit\":100,\"currency\":\"EUR\"}";

            string digest = "SHA-256=" + Convert.ToBase64String(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(body)));

            LiteralEsito.Text += "<p>body: " + body + "</p>";

            LiteralEsito.Text += "<p>digest: " + digest + "</p>";

            string stringToSign = "(request-target): post /wally-services/protocol/tests/signature\n" +
                "host: staging.authservices.satispay.com\n" +
                "date: " + date + "\n" +
                "digest: " + digest;

            // Load the private key from the PEM file
            string privateKeyFilePath = Server.MapPath("/pem/private.pem");
            string privateKeyPem = File.ReadAllText(privateKeyFilePath);

            var pemReader = new PemReader(new StringReader(privateKeyPem));
            var keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

            // Compute the SHA-256 hash of the input string
            var shaDigest = new Sha256Digest();
            byte[] message = Encoding.UTF8.GetBytes(stringToSign);
            shaDigest.BlockUpdate(message, 0, message.Length);
            byte[] hash = new byte[shaDigest.GetDigestSize()];
            shaDigest.DoFinal(hash, 0);

            //// Create an RSA signer and initialize it with the private key and the SHA-256 digest
            var signer = new RsaDigestSigner(new Sha256Digest());
            signer.Init(true, privateKey);
            signer.BlockUpdate(hash, 0, hash.Length);

            //// Generate the signature and convert it to a Base64 string
            byte[] signature = signer.GenerateSignature();
            string base64Signature = Convert.ToBase64String(signature);

            LiteralEsito.Text += "<p>stringToSign: " + stringToSign + "</p>";

            LiteralEsito.Text += "<p>private key: " + privateKeyPem + "</p>";

            LiteralEsito.Text += "<p>base64Signature: " + base64Signature + "</p>";


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