using System;
using System.Security.Cryptography;
using System.Text;

namespace BCrypt.Net
{
    internal static class SaltGenerator
    {
        /// <summary>
        /// RandomNumberGenerator.Create calls RandomNumberGenerator.Create("System.Security.Cryptography.RandomNumberGenerator"), which will create an instance of RNGCryptoServiceProvider.
        /// https://msdn.microsoft.com/en-us/library/42ks8fz1
        /// </summary>
        private static readonly RandomNumberGenerator RngCsp = RandomNumberGenerator.Create(); // secure PRNG

        /// <summary>
        ///  Generate a salt for use with the <see cref="BCrypt.HashPassword(string, string)"/> method.
        /// </summary>
        /// <param name="workFactor">The log2 of the number of rounds of hashing to apply - the work
        ///                          factor therefore increases as 2**workFactor.</param>
        /// <param name="bcryptMinorRevision"></param>
        /// <exception cref="ArgumentOutOfRangeException">Work factor must be between 4 and 31</exception>
        /// <returns>A base64 encoded salt value.</returns>
        /// <exception cref="ArgumentException">BCrypt Revision should be a, b, x or y</exception>
        public static string GenerateSalt(int workFactor, char bcryptMinorRevision = BCrypt.DefaultHashVersion)
        {
            if (workFactor < BCrypt.MinRounds || workFactor > BCrypt.MaxRounds)
            {
                throw new ArgumentOutOfRangeException(nameof(workFactor), workFactor, $"The work factor must be between {BCrypt.MinRounds} and {BCrypt.MaxRounds} (inclusive)");
            }

            if (bcryptMinorRevision != 'a' && bcryptMinorRevision != 'b' && bcryptMinorRevision != 'x' && bcryptMinorRevision != 'y')
            {
                throw new ArgumentException("BCrypt Revision should be a, b, x or y", nameof(bcryptMinorRevision));
            }

#if HAS_SPAN_RNG
            Span<char> saltBuffer = stackalloc char[29];
            var pos = 0;
            saltBuffer[pos++] = '$';
            saltBuffer[pos++] = '2';
            saltBuffer[pos++] = bcryptMinorRevision;
            saltBuffer[pos++] = '$';
            saltBuffer[pos++] = (char)((workFactor / 10) + '0');
            saltBuffer[pos++] = (char)((workFactor % 10) + '0');
            saltBuffer[pos++] = '$';
            WriteBase64Salt(saltBuffer, pos);
            return new string(saltBuffer);
#else
            byte[] saltBytes = new byte[BCrypt.BCryptSaltLen];
            RngCsp.GetBytes(saltBytes);
            var result = new StringBuilder(29);
            result.Append("$2").Append(bcryptMinorRevision).Append('$').Append(workFactor.ToString("D2")).Append('$');
            result.Append(Base64.EncodeBase64(saltBytes, saltBytes.Length));

            return result.ToString();
#endif
        }

#if HAS_SPAN_RNG
        private static void WriteBase64Salt(Span<char> outBuffer, int pos)
        {
            Span<byte> saltBytes = stackalloc byte[BCrypt.BCryptSaltLen];
            RandomNumberGenerator.Fill(saltBytes);
            Base64.EncodeBase64(saltBytes, saltBytes.Length, outBuffer, pos);
        }
#endif
    }
}
