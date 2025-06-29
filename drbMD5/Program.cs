namespace drbMD5;

public class Program
{
    static void Main()
    {
        string input1 = "Hello, World!";
        string hash1 = bMD5.Hash(input1);
        Console.WriteLine($"MD5 hash of '{input1}':");
        Console.WriteLine(hash1);
        Console.WriteLine();

        byte[] binaryData = "\x01\x02\x03\x04\x05\x06"u8.ToArray();
        byte[] hashBytes = bMD5.ComputeHash(binaryData);
        
        Console.WriteLine("MD5 hash of binary data:");
        Console.WriteLine(BitConverter.ToString(hashBytes).Replace("-", ""));
        Console.WriteLine($"As lowercase hex: {BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant()}");
        Console.WriteLine();

        Console.WriteLine("MD5 hash of empty string:");
        Console.WriteLine(bMD5.Hash(""));
    }
}