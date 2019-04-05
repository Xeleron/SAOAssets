using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Decrypt
{
    internal static class Program
    {
        private static CryptionParam _param;

        private static readonly char[] CodeConverTable =
        {
            'f',
            'n',
            '5',
            'h',
            's',
            'e',
            'm',
            '4',
            'v',
            'c',
            '3',
            '9',
            'p',
            'j',
            't',
            '8',
            'b',
            '2',
            'k',
            '7',
            'g',
            '0',
            '1',
            'u',
            '6',
            'w',
            'y',
            '_',
            'o',
            'i',
            'r',
            'a',
            'l',
            'd',
            'q',
            '-',
            'x',
            'z',
            '.',
            '/',
            'Z'
        };

        private static readonly char[] DeCodeConverTable =
        {
            'a',
            'b',
            'c',
            'd',
            'e',
            'f',
            'g',
            'h',
            'i',
            'j',
            'k',
            'l',
            'm',
            'n',
            'o',
            'p',
            'q',
            'r',
            's',
            't',
            'u',
            'v',
            'w',
            'x',
            'y',
            'z',
            '0',
            '1',
            '2',
            '3',
            '4',
            '5',
            '6',
            '7',
            '8',
            '9',
            '.',
            '_',
            '-',
            '/',
            'Z'
        };

        private static void Main()
        {
            //Console.WriteLine(DecodeReleaseServerResourceName("hiizaxgm8"));
            //Console.ReadKey();
            var test = new WebClient().DownloadData(
               "https://saoif-com.sslcs.cdngc.net/resources/3pc56gmd4fz1Qe7G");
            //CryptionBinaryAsync(false, "KaNaMeCho07", "vh6SyfV6qrjZma0w", 100, test);
            //File.WriteAllBytes("3pc56gmd4fz1Qe7G_JP_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources_fc/3pc56gmd4fz1Qe7G");
            //CryptionBinaryAsync(false, "KaNaMeCho07", "vh6SyfV6qrjZma0w", 100, test);
            //File.WriteAllBytes("3pc56gmd4fz1Qe7G_EN_AGAIN.txt", _param.CryptionResult);
            test = new WebClient().DownloadData(
                "https://saoif-com.sslcs.cdngc.net/resources/hiizaxgm8/rk2EZgv6IfDnsF6o");
            CryptionBinaryAsync(false, "RiKuOu08", "gAf69pPr5srBi3ar", 100, test);
            File.WriteAllBytes("rk2EZgv6IfDnsF6o_JP_RELEASE_AGAIN.txt", _param.CryptionResult);
            test = new WebClient().DownloadData(
                "https://saoif-com.sslcs.cdngc.net/resources/ie6n22b4/rk2EZgv6IfDnsF6o");
            CryptionBinaryAsync(false, "RiKuOu08", "gAf69pPr5srBi3ar", 100, test);
            File.WriteAllBytes("rk2EZgv6IfDnsF6o_JP_REVIEW_AGAIN.txt", _param.CryptionResult);
            test = new WebClient().DownloadData(
                "https://saoif-com.sslcs.cdngc.net/resources_fc/hiizaxgm8/rk2EZgv6IfDnsF6o");
            CryptionBinaryAsync(false, "RiKuOu08", "gAf69pPr5srBi3ar", 100, test);
            File.WriteAllBytes("rk2EZgv6IfDnsF6o_EN_RELEASE_AGAIN.txt", _param.CryptionResult);
            test = new WebClient().DownloadData(
                "https://saoif-com.sslcs.cdngc.net/resources_fc/ie6n22b4/rk2EZgv6IfDnsF6o");
            CryptionBinaryAsync(false, "RiKuOu08", "gAf69pPr5srBi3ar", 100, test);
            File.WriteAllBytes("rk2EZgv6IfDnsF6o_EN_REVIEW_AGAIN.txt", _param.CryptionResult);
            test = new WebClient().DownloadData(
                "https://saoif-com.sslcs.cdngc.net/resources/gte5bdyu9/rk2EZgv6IfDnsF6o");
            CryptionBinaryAsync(false, "RiKuOu08", "gAf69pPr5srBi3ar", 100, test);
            File.WriteAllBytes("rk2EZgv6IfDnsF6o_JP_gte5bdyu9_AGAIN.txt", _param.CryptionResult);
            test = new WebClient().DownloadData(
                "https://saoif-com.sslcs.cdngc.net/resources/fzin1ace0/rk2EZgv6IfDnsF6o");
            CryptionBinaryAsync(false, "RiKuOu08", "gAf69pPr5srBi3ar", 100, test);
            File.WriteAllBytes("rk2EZgv6IfDnsF6o_JP_fzin1ace0_AGAIN.txt", _param.CryptionResult);
            test = new WebClient().DownloadData(
                "https://saoif-com.sslcs.cdngc.net/resources/ey9ebq2p1/rk2EZgv6IfDnsF6o");
            CryptionBinaryAsync(false, "RiKuOu08", "gAf69pPr5srBi3ar", 100, test);
            File.WriteAllBytes("rk2EZgv6IfDnsF6o_JP_ey9ebq2p1_AGAIN.txt", _param.CryptionResult);




            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources/9sfg5bsc/rk2EZgv6IfDnsF6o");
            //CryptionBinaryAsync(false, "KoBunSha06", "prM2uGjxTe7dYa9b", 100, test);
            //File.WriteAllBytes("IOS_rk2EZgv6IfDnsF6o_JP_RELEASE_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources/8r7hu8a25/rk2EZgv6IfDnsF6o");
            //CryptionBinaryAsync(false, "KoBunSha06", "prM2uGjxTe7dYa9b", 100, test);
            //File.WriteAllBytes("IOS_rk2EZgv6IfDnsF6o_JP_REVIEW_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources_fc/8r7hu8a25/rk2EZgv6IfDnsF6o");
            //CryptionBinaryAsync(false, "KoBunSha06", "prM2uGjxTe7dYa9b", 100, test);
            //File.WriteAllBytes("IOS_rk2EZgv6IfDnsF6o_EN_RELEASE_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources_fc/9sfg5bsc/rk2EZgv6IfDnsF6o");
            //CryptionBinaryAsync(false, "KoBunSha06", "prM2uGjxTe7dYa9b", 100, test);
            //File.WriteAllBytes("IOS_rk2EZgv6IfDnsF6o_EN_REVIEW_AGAIN.txt", _param.CryptionResult);





            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources_fc/hiizaxgm8/pv5oEtjD3aMwuCgz");
            //CryptionBinaryAsync(false, "ToShiMa03", "tj3GjrS9yVfs8jWo", 100, test);
            //File.WriteAllBytes("pv5oEtjD3aMwuCgz.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources_fc/hiizaxgm8/clBoG1rvRpgEa5du");
            //CryptionBinaryAsync(false, "BuKuRo23", "jmN6s3trUh9jgVe", 100, test);
            //File.WriteAllBytes("clBoG1rvRpgEa5du_EN_RELEASE_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources_fc/ie6n22b4/dpWp6BpzrAs9Qmyz");
            //CryptionBinaryAsync(false, "BuKuRo23", "jmN6s3trUh9jgVe", 100, test);
            //File.WriteAllBytes("dpWp6BpzrAs9Qmyz_EN_REVIEW_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources/ie6n22b4/a7zfiCaoM2jbVPrj");
            //CryptionBinaryAsync(false, "BuKuRo23", "jmN6s3trUh9jgVe", 100, test);
            //File.WriteAllBytes("a7zfiCaoM2jbVPrj_JP_RELEASE_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources/hiizaxgm8/bwH5rgw8aUe4ljtq");
            //CryptionBinaryAsync(false, "BuKuRo23", "jmN6s3trUh9jgVe", 100, test);
            //File.WriteAllBytes("bwH5rgw8aUe4ljtq_JP_REVIEW_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources/ie6n22b4/bwH5rgw8aUe4ljtq");
            //CryptionBinaryAsync(false, "BuKuRo23", "jmN6s3trUh9jgVe", 100, test);
            //File.WriteAllBytes("bwH5rgw8aUe4ljtq_JP_RELEASE_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources_fc/hiizaxgm8/bwH5rgw8aUe4ljtq");
            //CryptionBinaryAsync(false, "BuKuRo23", "jmN6s3trUh9jgVe", 100, test);
            //File.WriteAllBytes("bwH5rgw8aUe4ljtq_EN_RELEASE_AGAIN.txt", _param.CryptionResult);
            //test = new WebClient().DownloadData(
            //    "https://saoif-com.sslcs.cdngc.net/resources_fc/ie6n22b4/bwH5rgw8aUe4ljtq");
            //CryptionBinaryAsync(false, "BuKuRo23", "jmN6s3trUh9jgVe", 100, test);
            //File.WriteAllBytes("bwH5rgw8aUe4ljtq_EN_REVIEW_AGAIN.txt", _param.CryptionResult);
        }

        private static string EncodeReleaseServerResourceName(string name)
        {
            var array = new char[name.Length];
            for (var i = 0; i < name.Length; i++)
            {
                var c = name[i];
                if (c >= 'a' && c <= 'z')
                    array[i] = CodeConverTable[c - 'a'];
                else if (c >= '0' && c <= '9')
                    array[i] = CodeConverTable[c - '0' + '\u001a'];
                else
                    switch (c)
                    {
                        case '.':
                            array[i] = CodeConverTable[36];
                            break;
                        case '_':
                            array[i] = CodeConverTable[37];
                            break;
                        case '-':
                            array[i] = CodeConverTable[38];
                            break;
                        case '/':
                            array[i] = CodeConverTable[39];
                            break;
                        default:
                            array[i] = CodeConverTable[40];
                            break;
                    }
            }

            return new string(array);
        }

        private static string DecodeReleaseServerResourceName(string name)
        {
            var array = new char[name.Length];
            for (var i = 0; i < name.Length; i++)
            {
                var c = name[i];
                try
                {
                    array[i] = DeCodeConverTable[Array.IndexOf(CodeConverTable, c)];
                }
                catch
                {
                    array[i] = 'Z';
                }
            }

            return new string(array);
        }

        private static string DecryptPasscode(string text)
        {
            var array = Convert.FromBase64String(text);
            var array2 = new byte[array.Length];
            using (var memoryStream = new MemoryStream(array))
            {
                using (var cryptoStream = new CryptoStream(memoryStream,
                    CreateAesSetting().CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.Read(array2, 0, array2.Length);
                    return Encoding.UTF8.GetString(array2).TrimEnd(new char[1]);
                }
            }
        }

        private static RijndaelManaged CreateAesSetting()
        {
            var rijndaelManaged = new RijndaelManaged
            {
                BlockSize = 128,
                KeySize = 128,
                Padding = PaddingMode.Zeros,
                Mode = CipherMode.ECB
            };
            var bytes = Encoding.UTF8.GetBytes("2eeee02d3dc3ef6c");
            rijndaelManaged.Key = bytes;
            return rijndaelManaged;
        }

        private static void ThreadCryptionTask()
        {
            _param.CryptionResult = null;
            var rijndaelManaged = new RijndaelManaged
            {
                KeySize = 128,
                BlockSize = 128
            };
            var rfc2898DeriveBytes =
                new Rfc2898DeriveBytes(_param.Password, _param.Salt) {IterationCount = _param.IterationCount};
            rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
            rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
            var cryptoTransform =
                !_param.EncryptionMode ? rijndaelManaged.CreateDecryptor() : rijndaelManaged.CreateEncryptor();
            var cryptionResult = cryptoTransform.TransformFinalBlock(_param.SrcBinary, 0, _param.SrcBinary.Length);
            cryptoTransform.Dispose();
            _param.CryptionResult = cryptionResult;
        }

        private static void CryptionBinaryAsync(bool encryption_mode, string password, string salt, int iteration_count,
            byte[] src_binary)
        {
            _param = new CryptionParam(encryption_mode, password, GetSaltBinay(salt), iteration_count, src_binary);
            ThreadCryptionTask();
        }

        private static byte[] GetSaltBinay(string salt_code)
        {
            var array = new byte[16];
            var bytes = Encoding.UTF8.GetBytes(salt_code);
            for (var i = 0; i < 16; i++)
                if (i < bytes.Length)
                    array[i] = bytes[i];
                else
                    array[i] = 0;
            return array;
        }
    }

    internal class CryptionParam
    {
        public byte[] CryptionResult;

        public bool EncryptionMode;

        public int IterationCount;

        public string Password;

        public byte[] Salt;

        public byte[] SrcBinary;

        public CryptionParam(bool encryption_mode, string password, byte[] salt, int iteration_count, byte[] src_binary)
        {
            EncryptionMode = encryption_mode;
            Password = password;
            Salt = salt;
            IterationCount = iteration_count;
            SrcBinary = src_binary;
            CryptionResult = null;
        }
    }
}