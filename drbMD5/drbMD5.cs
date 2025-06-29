using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace drbMD5;

public static unsafe class bMD5
{
    [StructLayout(LayoutKind.Explicit)]
    private struct Md5State
    {
        [FieldOffset(0)] public uint A;
        [FieldOffset(4)] public uint B;
        [FieldOffset(8)] public uint C;
        [FieldOffset(12)] public uint D;
    }

    private const int BlockSize = 64;
    private const int PaddingThreshold = 56;

    public static string Hash(string input)
    {
        byte[] hashBytes = ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    public static byte[] ComputeHash(byte[] message)
    {
        Md5State state = new()
        {
            A = 0x67452301,
            B = 0xEFCDAB89,
            C = 0x98BADCFE,
            D = 0x10325476
        };

        int totalLength = message.Length;
        ulong totalBits = (ulong)totalLength << 3;

        fixed (byte* ptr = message)
        {
            byte* current = ptr;
            int remaining = totalLength;

            while (remaining >= BlockSize)
            {
                ProcessBlock(ref state, current);
                current += BlockSize;
                remaining -= BlockSize;
            }

            Span<byte> finalBlock = stackalloc byte[128];
            ref byte fbRef = ref MemoryMarshal.GetReference(finalBlock);
            
            if (remaining > 0)
            {
                Unsafe.CopyBlockUnaligned(ref fbRef, ref *current, (uint)remaining);
            }
            
            Unsafe.Add(ref fbRef, remaining) = 0x80;
            
            int padLength = remaining < PaddingThreshold ? 56 : 120;
            int clearStart = remaining + 1;
            int clearLength = padLength - remaining - 1;
            if (clearLength > 0)
            {
                Unsafe.InitBlockUnaligned(ref Unsafe.Add(ref fbRef, clearStart), 0, (uint)clearLength);
            }

            Unsafe.As<byte, ulong>(ref Unsafe.Add(ref fbRef, padLength)) = totalBits;

            fixed (byte* fbPtr = finalBlock)
            {
                ProcessBlock(ref state, fbPtr);
                if (remaining >= PaddingThreshold)
                {
                    ProcessBlock(ref state, fbPtr + BlockSize);
                }
            }
        }

        return
        [
            (byte)state.A, (byte)(state.A >> 8), (byte)(state.A >> 16), (byte)(state.A >> 24),
            (byte)state.B, (byte)(state.B >> 8), (byte)(state.B >> 16), (byte)(state.B >> 24),
            (byte)state.C, (byte)(state.C >> 8), (byte)(state.C >> 16), (byte)(state.C >> 24),
            (byte)state.D, (byte)(state.D >> 8), (byte)(state.D >> 16), (byte)(state.D >> 24)
        ];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint RotateLeft(uint value, int bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }

    private static void ProcessBlock(ref Md5State state, byte* block)
    {
        uint a = state.A;
        uint b = state.B;
        uint c = state.C;
        uint d = state.D;

        uint* m = (uint*)block;
        
        uint m0 = m[0];   uint m1 = m[1];   uint m2 = m[2];   uint m3 = m[3];
        uint m4 = m[4];   uint m5 = m[5];   uint m6 = m[6];   uint m7 = m[7];
        uint m8 = m[8];   uint m9 = m[9];   uint m10 = m[10]; uint m11 = m[11];
        uint m12 = m[12]; uint m13 = m[13]; uint m14 = m[14]; uint m15 = m[15];

        a = b + RotateLeft(a + ((b & c) | (~b & d)) + m0 + 0xD76AA478, 7);
        d = a + RotateLeft(d + ((a & b) | (~a & c)) + m1 + 0xE8C7B756, 12);
        c = d + RotateLeft(c + ((d & a) | (~d & b)) + m2 + 0x242070DB, 17);
        b = c + RotateLeft(b + ((c & d) | (~c & a)) + m3 + 0xC1BDCEEE, 22);
        
        a = b + RotateLeft(a + ((b & c) | (~b & d)) + m4 + 0xF57C0FAF, 7);
        d = a + RotateLeft(d + ((a & b) | (~a & c)) + m5 + 0x4787C62A, 12);
        c = d + RotateLeft(c + ((d & a) | (~d & b)) + m6 + 0xA8304613, 17);
        b = c + RotateLeft(b + ((c & d) | (~c & a)) + m7 + 0xFD469501, 22);
        
        a = b + RotateLeft(a + ((b & c) | (~b & d)) + m8 + 0x698098D8, 7);
        d = a + RotateLeft(d + ((a & b) | (~a & c)) + m9 + 0x8B44F7AF, 12);
        c = d + RotateLeft(c + ((d & a) | (~d & b)) + m10 + 0xFFFF5BB1, 17);
        b = c + RotateLeft(b + ((c & d) | (~c & a)) + m11 + 0x895CD7BE, 22);
        
        a = b + RotateLeft(a + ((b & c) | (~b & d)) + m12 + 0x6B901122, 7);
        d = a + RotateLeft(d + ((a & b) | (~a & c)) + m13 + 0xFD987193, 12);
        c = d + RotateLeft(c + ((d & a) | (~d & b)) + m14 + 0xA679438E, 17);
        b = c + RotateLeft(b + ((c & d) | (~c & a)) + m15 + 0x49B40821, 22);

        a = b + RotateLeft(a + ((b & d) | (c & ~d)) + m1 + 0xF61E2562, 5);
        d = a + RotateLeft(d + ((a & c) | (b & ~c)) + m6 + 0xC040B340, 9);
        c = d + RotateLeft(c + ((d & b) | (a & ~b)) + m11 + 0x265E5A51, 14);
        b = c + RotateLeft(b + ((c & a) | (d & ~a)) + m0 + 0xE9B6C7AA, 20);
        
        a = b + RotateLeft(a + ((b & d) | (c & ~d)) + m5 + 0xD62F105D, 5);
        d = a + RotateLeft(d + ((a & c) | (b & ~c)) + m10 + 0x02441453, 9);
        c = d + RotateLeft(c + ((d & b) | (a & ~b)) + m15 + 0xD8A1E681, 14);
        b = c + RotateLeft(b + ((c & a) | (d & ~a)) + m4 + 0xE7D3FBC8, 20);
        
        a = b + RotateLeft(a + ((b & d) | (c & ~d)) + m9 + 0x21E1CDE6, 5);
        d = a + RotateLeft(d + ((a & c) | (b & ~c)) + m14 + 0xC33707D6, 9);
        c = d + RotateLeft(c + ((d & b) | (a & ~b)) + m3 + 0xF4D50D87, 14);
        b = c + RotateLeft(b + ((c & a) | (d & ~a)) + m8 + 0x455A14ED, 20);
        
        a = b + RotateLeft(a + ((b & d) | (c & ~d)) + m13 + 0xA9E3E905, 5);
        d = a + RotateLeft(d + ((a & c) | (b & ~c)) + m2 + 0xFCEFA3F8, 9);
        c = d + RotateLeft(c + ((d & b) | (a & ~b)) + m7 + 0x676F02D9, 14);
        b = c + RotateLeft(b + ((c & a) | (d & ~a)) + m12 + 0x8D2A4C8A, 20);

        a = b + RotateLeft(a + (b ^ c ^ d) + m5 + 0xFFFA3942, 4);
        d = a + RotateLeft(d + (a ^ b ^ c) + m8 + 0x8771F681, 11);
        c = d + RotateLeft(c + (d ^ a ^ b) + m11 + 0x6D9D6122, 16);
        b = c + RotateLeft(b + (c ^ d ^ a) + m14 + 0xFDE5380C, 23);
        
        a = b + RotateLeft(a + (b ^ c ^ d) + m1 + 0xA4BEEA44, 4);
        d = a + RotateLeft(d + (a ^ b ^ c) + m4 + 0x4BDECFA9, 11);
        c = d + RotateLeft(c + (d ^ a ^ b) + m7 + 0xF6BB4B60, 16);
        b = c + RotateLeft(b + (c ^ d ^ a) + m10 + 0xBEBFBC70, 23);
        
        a = b + RotateLeft(a + (b ^ c ^ d) + m13 + 0x289B7EC6, 4);
        d = a + RotateLeft(d + (a ^ b ^ c) + m0 + 0xEAA127FA, 11);
        c = d + RotateLeft(c + (d ^ a ^ b) + m3 + 0xD4EF3085, 16);
        b = c + RotateLeft(b + (c ^ d ^ a) + m6 + 0x04881D05, 23);
        
        a = b + RotateLeft(a + (b ^ c ^ d) + m9 + 0xD9D4D039, 4);
        d = a + RotateLeft(d + (a ^ b ^ c) + m12 + 0xE6DB99E5, 11);
        c = d + RotateLeft(c + (d ^ a ^ b) + m15 + 0x1FA27CF8, 16);
        b = c + RotateLeft(b + (c ^ d ^ a) + m2 + 0xC4AC5665, 23);

        a = b + RotateLeft(a + (c ^ (b | ~d)) + m0 + 0xF4292244, 6);
        d = a + RotateLeft(d + (b ^ (a | ~c)) + m7 + 0x432AFF97, 10);
        c = d + RotateLeft(c + (a ^ (d | ~b)) + m14 + 0xAB9423A7, 15);
        b = c + RotateLeft(b + (d ^ (c | ~a)) + m5 + 0xFC93A039, 21);
        
        a = b + RotateLeft(a + (c ^ (b | ~d)) + m12 + 0x655B59C3, 6);
        d = a + RotateLeft(d + (b ^ (a | ~c)) + m3 + 0x8F0CCC92, 10);
        c = d + RotateLeft(c + (a ^ (d | ~b)) + m10 + 0xFFEFF47D, 15);
        b = c + RotateLeft(b + (d ^ (c | ~a)) + m1 + 0x85845DD1, 21);
        
        a = b + RotateLeft(a + (c ^ (b | ~d)) + m8 + 0x6FA87E4F, 6);
        d = a + RotateLeft(d + (b ^ (a | ~c)) + m15 + 0xFE2CE6E0, 10);
        c = d + RotateLeft(c + (a ^ (d | ~b)) + m6 + 0xA3014314, 15);
        b = c + RotateLeft(b + (d ^ (c | ~a)) + m13 + 0x4E0811A1, 21);
        
        a = b + RotateLeft(a + (c ^ (b | ~d)) + m4 + 0xF7537E82, 6);
        d = a + RotateLeft(d + (b ^ (a | ~c)) + m11 + 0xBD3AF235, 10);
        c = d + RotateLeft(c + (a ^ (d | ~b)) + m2 + 0x2AD7D2BB, 15);
        b = c + RotateLeft(b + (d ^ (c | ~a)) + m9 + 0xEB86D391, 21);

        state.A += a;
        state.B += b;
        state.C += c;
        state.D += d;
    }
}