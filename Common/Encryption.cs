using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Common;

public static class Encryption
{
    private static byte[]? _masterKey;

    public static void Initialize(string masterKeyPath)
    {
        if (string.IsNullOrEmpty(masterKeyPath))
        {
            throw new ArgumentException($"'{nameof(masterKeyPath)}' cannot be null or empty.", nameof(masterKeyPath));
        }

        string keyBase64 = File.ReadAllText(masterKeyPath, Encoding.UTF8).Trim();
        _masterKey = Convert.FromBase64String(keyBase64);

        if (_masterKey.Length != 32)
        {
            throw new ArgumentException("Master key must be 32 bytes for AES-256.", nameof(masterKeyPath));
        }
    }

    public static string Encrypt(string plainText)
    {
        if (_masterKey == null) throw new InvalidOperationException("Encryption not initialized with master key.");

        using Aes aes = Aes.Create();
        aes.Key = _masterKey;
        aes.GenerateIV();

        using MemoryStream ms = new();
        ms.Write(aes.IV, 0, aes.IV.Length);

        using (CryptoStream cs = new(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        using (StreamWriter sw = new(cs))
        {
            sw.Write(plainText);
        }

        return Convert.ToBase64String(ms.ToArray());
    }

    public static string Decrypt(string cipherText)
    {
        if (_masterKey == null) throw new InvalidOperationException("Encryption not initialized with master key.");

        byte[] fullCipher = Convert.FromBase64String(cipherText);

        using Aes aes = Aes.Create();
        aes.Key = _masterKey;

        byte[] iv = new byte[aes.BlockSize / 8];
        byte[] cipher = new byte[fullCipher.Length - iv.Length];

        Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

        aes.IV = iv;

        using MemoryStream ms = new(cipher);
        using CryptoStream cs = new(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using StreamReader sr = new(cs);

        return sr.ReadToEnd();
    }
}
