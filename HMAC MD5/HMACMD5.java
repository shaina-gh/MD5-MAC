import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class HMACMD5 {

    private static final int[] S = {
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    };

    private static final int[] K = new int[64];
    
    static {
        for (int i = 0; i < 64; i++) {
            K[i] = (int)(long)((Math.abs(Math.sin(i + 1)) * (1L << 32))) & 0xFFFFFFFF;
        }
    }

    private static int leftRotate(int x, int c) {
        return (x << c) | (x >>> (32 - c));
    }

    public static byte[] md5(byte[] message) {
        // Initialize variables
        int a0 = 0x67452301;
        int b0 = 0xEFCDAB89;
        int c0 = 0x98BADCFE;
        int d0 = 0x10325476;

        // Pre-processing: padding with zeros
        int originalByteLen = message.length;
        long originalBitLen = (long)originalByteLen * 8;

        int paddingLength = (56 - (originalByteLen + 1) % 64 + 64) % 64;
        byte[] paddedMessage = Arrays.copyOf(message, originalByteLen + 1 + paddingLength + 8);
        paddedMessage[originalByteLen] = (byte) 0x80;

        // Append original length in bits as little-endian 64-bit integer
        ByteBuffer lenBuffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        lenBuffer.putLong(originalBitLen);
        System.arraycopy(lenBuffer.array(), 0, paddedMessage, originalByteLen + 1 + paddingLength, 8);

        // Process the message in 64-byte chunks
        for (int offset = 0; offset < paddedMessage.length; offset += 64) {
            ByteBuffer buffer = ByteBuffer.wrap(paddedMessage, offset, 64).order(ByteOrder.LITTLE_ENDIAN);
            int[] M = new int[16];
            for (int i = 0; i < 16; i++) {
                M[i] = buffer.getInt();
            }

            // Initialize hash value for this chunk
            int A = a0;
            int B = b0;
            int C = c0;
            int D = d0;

            // Main loop
            for (int i = 0; i < 64; i++) {
                int F, g;
                
                if (i < 16) {
                    F = (B & C) | (~B & D);
                    g = i;
                } else if (i < 32) {
                    F = (D & B) | (~D & C);
                    g = (5 * i + 1) % 16;
                } else if (i < 48) {
                    F = B ^ C ^ D;
                    g = (3 * i + 5) % 16;
                } else {
                    F = C ^ (B | ~D);
                    g = (7 * i) % 16;
                }

                F = F + A + K[i] + M[g];
                A = D;
                D = C;
                C = B;
                B = B + leftRotate(F, S[i]);
            }

            // Add this chunk's hash to result
            a0 += A;
            b0 += B;
            c0 += C;
            d0 += D;
        }

        // Output
        ByteBuffer out = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        out.putInt(a0);
        out.putInt(b0);
        out.putInt(c0);
        out.putInt(d0);
        return out.array();
    }

    public static String hmacMd5(byte[] key, byte[] message) {
        final int BLOCK_SIZE = 64;

        // Key preparation
        if (key.length > BLOCK_SIZE) {
            key = md5(key);
        }
        if (key.length < BLOCK_SIZE) {
            key = Arrays.copyOf(key, BLOCK_SIZE);
        }

        // Pad generation
        byte[] ipad = new byte[BLOCK_SIZE];
        byte[] opad = new byte[BLOCK_SIZE];

        for (int i = 0; i < BLOCK_SIZE; i++) {
            ipad[i] = (byte) (key[i] ^ 0x36);
            opad[i] = (byte) (key[i] ^ 0x5C);
        }

        // Inner hash
        byte[] inner = new byte[ipad.length + message.length];
        System.arraycopy(ipad, 0, inner, 0, ipad.length);
        System.arraycopy(message, 0, inner, ipad.length, message.length);
        byte[] innerHash = md5(inner);

        // Outer hash
        byte[] outer = new byte[opad.length + innerHash.length];
        System.arraycopy(opad, 0, outer, 0, opad.length);
        System.arraycopy(innerHash, 0, outer, opad.length, innerHash.length);
        byte[] mac = md5(outer);

        // Convert to hex string
        StringBuilder hex = new StringBuilder();
        for (byte b : mac) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    public static void main(String[] args) {
        byte[] key = "supersecretkey".getBytes();
        byte[] message = "This is a secure message.".getBytes();
        
        String mac = hmacMd5(key, message);
        
        System.out.println("This is a secure message.");
        System.out.println("Message Authentication Code (MAC) for the message: " + mac);
    }
}