package online.flowerinsnow.sm3sum;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class SM3Sum {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        ByteBuffer buffer = ByteBuffer.allocateDirect(4096);
        for (String arg : args) {
            try (FileChannel fc = FileChannel.open(Paths.get(arg), StandardOpenOption.READ)) {
                MessageDigest md = MessageDigest.getInstance("SM3");
                while (fc.read(buffer) != -1) {
                    buffer.flip();
                    md.update(buffer);
                    buffer.clear();
                }
                byte[] digest = md.digest();
                System.out.println(toHEX(digest) + "\t" + arg);
            } catch (IOException e) {
                System.err.println("sm3sum: " + arg + ": " + e);
            }
        }
    }

    private static String toHEX(byte[] bytes) {
        final char[] HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        char[] result = new char[bytes.length * 2];
        for (byte i = 0; i < bytes.length; i++) {
            byte left = (byte) ((bytes[i] >>> 4) & 0xF);
            byte right = (byte) (bytes[i] & 0xF);
            result[i * 2] = HEX[left];
            result[i * 2 + 1] = HEX[right];
        }
        return new String(result);
    }
}