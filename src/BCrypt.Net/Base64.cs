using System;
using System.Collections.Generic;
using System.Text;

namespace BCrypt.Net
{
    internal static class Base64
    {
#if HAS_SPAN
        /// <summary>
        ///  Encode a byte array using BCrypt's slightly-modified base64 encoding scheme. Note that this
        ///  is *not* compatible with the standard MIME-base64 encoding.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or
        ///                                     illegal values.</exception>
        /// <param name="byteArray">The byte array to encode.</param>
        /// <param name="length">   The number of bytes to encode.</param>
        /// <param name="outBuffer">The output buffer</param>
        /// <param name="pos">position in outBuffer to start writing from</param>
        /// <returns>Base64-encoded string.</returns>
        public static void EncodeBase64(Span<byte> byteArray, int length, Span<char> outBuffer, int pos = 0)
        {
            if (length <= 0 || length > byteArray.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }

            Span<char> encoded = outBuffer;

            int off = 0;
            while (off < length)
            {
                int c1 = byteArray[off++] & 0xff;
                encoded[pos++] = Base64Code[(c1 >> 2) & 0x3f];
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                int c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                encoded[pos++] = Base64Code[c2 & 0x3f];
            }
        }
#endif

        /// <summary>
        ///  Encode a byte array using BCrypt's slightly-modified base64 encoding scheme. Note that this
        ///  is *not* compatible with the standard MIME-base64 encoding.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or
        ///                                     illegal values.</exception>
        /// <param name="byteArray">The byte array to encode.</param>
        /// <param name="length">   The number of bytes to encode.</param>
        /// <returns>Base64-encoded string.</returns>
#if HAS_SPAN
        public static char[] EncodeBase64(Span<byte> byteArray, int length)
#else
        public static char[] EncodeBase64(byte[] byteArray, int length)
#endif
        {
            if (length <= 0 || length > byteArray.Length)
            {
                throw new ArgumentException("Invalid length", nameof(length));
            }

            int encodedSize = (int)Math.Ceiling((length * 4D) / 3);
            char[] encoded = new char[encodedSize];

            int pos = 0;
            int off = 0;
            while (off < length)
            {
                int c1 = byteArray[off++] & 0xff;
                encoded[pos++] = Base64Code[(c1 >> 2) & 0x3f];
                c1 = (c1 & 0x03) << 4;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                int c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 4) & 0x0f;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                c1 = (c2 & 0x0f) << 2;
                if (off >= length)
                {
                    encoded[pos++] = Base64Code[c1 & 0x3f];
                    break;
                }

                c2 = byteArray[off++] & 0xff;
                c1 |= (c2 >> 6) & 0x03;
                encoded[pos++] = Base64Code[c1 & 0x3f];
                encoded[pos++] = Base64Code[c2 & 0x3f];
            }

            return encoded;
        }

        /// <summary>
        ///  Decode a string encoded using BCrypt's base64 scheme to a byte array.
        ///  Note that this is *not* compatible with the standard MIME-base64 encoding.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when one or more arguments have unsupported or
        ///                                     illegal values.</exception>
        /// <param name="encodedString">The string to decode.</param>
        /// <param name="maximumBytes"> The maximum bytes to decode.</param>
        /// <returns>The decoded byte array.</returns>
        public static byte[] DecodeBase64(string encodedString, int maximumBytes)
        {
            int sourceLength = encodedString.Length;
            int outputLength = 0;

            if (maximumBytes <= 0)
            {
                throw new ArgumentException("Invalid maximum bytes value", nameof(maximumBytes));
            }

            byte[] result = new byte[maximumBytes];

            int position = 0;
            while (position < sourceLength - 1 && outputLength < maximumBytes)
            {
                int c1 = Char64(encodedString[position++]);
                int c2 = Char64(encodedString[position++]);
                if (c1 == -1 || c2 == -1)
                {
                    break;
                }

                result[outputLength] = (byte)((c1 << 2) | ((c2 & 0x30) >> 4));
                if (++outputLength >= maximumBytes || position >= sourceLength)
                {
                    break;
                }

                int c3 = Char64(encodedString[position++]);
                if (c3 == -1)
                {
                    break;
                }

                result[outputLength] = (byte)(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2));
                if (++outputLength >= maximumBytes || position >= sourceLength)
                {
                    break;
                }

                int c4 = Char64(encodedString[position++]);
                result[outputLength] = (byte)(((c3 & 0x03) << 6) | c4);

                ++outputLength;
            }

            return result;
        }

        /// <summary>
        ///  Look up the 3 bits base64-encoded by the specified character, range-checking against
        ///  conversion table.
        /// </summary>
        /// <param name="character">The base64-encoded value.</param>
        /// <returns>The decoded value of x.</returns>
        /// 
        private static int Char64(char character)
        {
            return character < 0 || character > Index64.Length ? -1 : Index64[character];
        }

        // Table for Base64 encoding
        private static readonly char[] Base64Code = {
            '.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
            'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
            'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
            'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9'
        };

        // Table for Base64 decoding
        private static readonly int[] Index64 = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, 0, 1, 54, 55,
            56, 57, 58, 59, 60, 61, 62, 63, -1, -1,
            -1, -1, -1, -1, -1, 2, 3, 4, 5, 6,
            7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
            -1, -1, -1, -1, -1, -1, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
            51, 52, 53, -1, -1, -1, -1, -1
        };
    }
}
