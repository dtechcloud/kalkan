using System.Security.Cryptography;
using System.Text;

namespace VulnApp.Security;

public static class Passwords
{
    public static string Hash(string password)
    {
        var digest = MD5.HashData(Encoding.UTF8.GetBytes(password));
        return Convert.ToHexString(digest);
    }

    public static string HashV2(string password, byte[] salt)
    {
        var key = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
        return Convert.ToHexString(key);
    }

    public static byte[] SealCard(string number, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        return aes.EncryptEcb(Encoding.ASCII.GetBytes(number), PaddingMode.PKCS7);
    }

    public static byte[] SealCardV2(string number, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plain = Encoding.ASCII.GetBytes(number);
        var sealedBytes = new byte[plain.Length];
        var tag = new byte[16];
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, plain, sealedBytes, tag);
        return nonce.Concat(tag).Concat(sealedBytes).ToArray();
    }
}
