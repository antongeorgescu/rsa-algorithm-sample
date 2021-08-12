using System;
using System.Security.Cryptography;
using System.Text;

namespace RSAAlgorithm2
{
    class Program
    {
        static UnicodeEncoding ByteConverter = new UnicodeEncoding();
        static RSACryptoServiceProvider RSA = null;
        
        static void Main(string[] args)
        {
            // enter string to encrypt
            Console.WriteLine("Enter the string to encrypt...");
            var textToEncrypt = Console.ReadLine();
            Console.WriteLine($"String to encrypt:{textToEncrypt}");

            // generate key pair and store in 2 different files
            Console.WriteLine("Generate key pair and store in 2 different files.");
            RSAKeyManagement.GenerateRsaKeyPair("privateKey.txt", "publicKey.txt");

            // load public key from its file and apply encryption
            Console.WriteLine("Load public key from its file and apply encryption.");
            RSA = RSAKeyManagement.PublicKeyFromPemFile("publicKey.txt");
            byte[] plaintext = ByteConverter.GetBytes(textToEncrypt);
            byte[] encryptedtext = RSAKeyManagement.Encryption(plaintext, RSA.ExportParameters(false), false);

            // load private key from its file and apply decryption
            Console.WriteLine("Load private key from its file and apply decryption.");
            RSA = RSAKeyManagement.PrivateKeyFromPemFile("privateKey.txt");
            byte[] decryptedtex = RSAKeyManagement.Decryption(encryptedtext,
            RSA.ExportParameters(true), false);
            var decryptedText = ByteConverter.GetString(decryptedtex);

            // display the decrypted string
            Console.WriteLine($"Decrypted string:{decryptedText}");
            Console.WriteLine("Press any key to exit...");
            Console.ReadLine();
        }
    }
}
