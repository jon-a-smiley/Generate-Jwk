using GenerateRsaJwk.Enums;
using Jwk.Generator;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GenerateRsaJwk
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("GenerateRsaJwk Console App");
            Console.WriteLine("Generating 2048 RSA Key");
            IRsaKeyGenerator generator = new RsaKeyGenerator();
            var length = "<INSERT_HERE>".ToCharArray().Length;
            var clientLength = "<INSERT_HERE>".ToCharArray().Length;
            RsaSecurityKey key = generator.GenerateKey(2048, RandomKey(length));

            Console.WriteLine($"Generated RSA Key with size: {key.KeySize}");

            Console.WriteLine($"Generate ClientId: {RandomKey(clientLength)}");

            Console.WriteLine($"Generate DecryptionKey: {DecryptionKeys()}");

            //Use the custom ToJwk extension to convert the RSA Key in JWK object
            var alg = RsaAlgorithm.Rs256;
            JsonWebKey jwk1 = key.ToJwk(alg, true);
            JsonWebKey jwkPublic = key.ToJwk(alg, false);

            // Use JsonWebKeyConverter to convert the RSA Key in JWK object
            JsonWebKey jwk2 = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
            var algorithmInfo = alg.GetJsonWebAlgorithm();
            jwk2.Use = algorithmInfo?.PublicKeyUse;
            jwk2.Alg = algorithmInfo?.Name;

            //Assertion. JWK.ToString returns the formatted string: GetType(), Use: 'value', Kid: 'value', Kty: 'value', InternalId: 'value'.
            Debug.Assert(jwk1.ToString() == jwk2.ToString());

            //output the JWK string
            ConvertToStringWithJsonExtensions1(jwk1, jwkPublic);
            ConvertToSigningKeyFormat(jwk1);
            //ConvertToStringWithJsonExtensions2(jwk1, jwkPublic);
            //ConvertToStringWithJsonSerializer(jwk1, jwkPublic);
            //ConvertToStringManually(jwk1, jwkPublic);

            Console.ReadLine();
        }

        static string DecryptionKeys()
        {
            var aes = new AesManaged();
            aes.GenerateKey();
            aes.GenerateIV();
            return Convert.ToBase64String(aes.Key);
        }

        static string RandomKey(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        static void ConvertToSigningKeyFormat(JsonWebKey jwk)
        {
            var builder = new StringBuilder("<RSAKeyValue>");
            builder.Append($"<Modulus>{jwk.N}</Modulus>");
            builder.Append($"<Exponent>{jwk.E}</Exponent>");
            builder.Append($"<P>{jwk.P}</P>");
            builder.Append($"<Q>{jwk.Q}</Q>");
            builder.Append($"<DP>{jwk.DP}</DP>");
            builder.Append($"<DQ>{jwk.DQ}</DQ>");
            builder.Append($"<InverseQ>{jwk.QI}</InverseQ>");
            builder.Append($"<D>{jwk.D}</D>");
            builder.Append("</RSAKeyValue>");
            Console.WriteLine(builder.ToString());
        }

        static void ConvertToStringManually(JsonWebKey jwk, JsonWebKey jwkPublic)
        {
            Console.WriteLine($"------------------------------------------------------------");
            Console.WriteLine($"Serialize the JWK to String with custom classes (Manually)");
            Console.WriteLine($"JWK:");
            Console.WriteLine(jwk.SerializeToJson());
            Console.WriteLine();
            Console.WriteLine($"JWK (public key):");
            Console.WriteLine(jwkPublic.SerializeToJson());
            Console.WriteLine();
        }
        static void ConvertToStringWithJsonExtensions1(JsonWebKey jwk, JsonWebKey jwkPublic)
        {
            Console.WriteLine($"------------------------------------------------------------");
            Console.WriteLine($"Serialize the JWK to String with JsonExtensions.SerializeToJson");
            Console.WriteLine($"JWK Raw:");
            Console.WriteLine(JsonExtensions.SerializeToJson(jwk));
            Console.WriteLine();
            Console.WriteLine($"JWK (public key):");
            Console.WriteLine(JsonExtensions.SerializeToJson(jwkPublic).Replace("\"", "\\\""));
            Console.WriteLine();
        }

        static void ConvertToStringWithJsonExtensions2(JsonWebKey jwk, JsonWebKey jwkPublic)
        {
            Console.WriteLine($"------------------------------------------------------------");
            Console.WriteLine($"Serialize the JWK to String with JsonExtensions.SerializeToJson and indent the output");
            Console.WriteLine($"JWK Raw:");
            var jwkString = JsonExtensions.SerializeToJson(jwk);
            Console.WriteLine(JValue.Parse(jwkString).ToString(Formatting.Indented));
            Console.WriteLine();
            Console.WriteLine($"JWK (public key):");
            var jwkPublicString = JsonExtensions.SerializeToJson(jwkPublic);
            Console.WriteLine(JValue.Parse(jwkPublicString).ToString(Formatting.Indented));
            Console.WriteLine();
        }
        static void ConvertToStringWithJsonSerializer(JsonWebKey jwk, JsonWebKey jwkPublic)
        {
            Console.WriteLine($"------------------------------------------------------------");
            Console.WriteLine($"Serialize the JWK to String with System.Text.Json.JsonSerializer.Serialize");
            Console.WriteLine($"JWK Raw:");
            var options = new JsonSerializerOptions { WriteIndented = true };
            string jwkString = System.Text.Json.JsonSerializer.Serialize(jwk, options);
            Console.WriteLine(jwkString);
            Console.WriteLine();
            Console.WriteLine($"JWK (public key):");
            var jwkPublicString = System.Text.Json.JsonSerializer.Serialize(jwkPublic, options);
            Console.WriteLine(JValue.Parse(jwkPublicString).ToString(Formatting.Indented));
            Console.WriteLine();
        }
    }
}