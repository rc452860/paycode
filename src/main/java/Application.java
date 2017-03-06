import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Date;

/**
 * Created by rc452 on 2017/3/5.
 */
public class Application {
    public static byte[] get8BitBytes(long data) {
        byte[] result = new byte[8];
        int[] shift = {56, 48, 40, 32, 24, 16, 8, 0};
        long mask = 0xFF;
        for (int i = 0; i < 8; i++) {
            result[i] = (byte) ((data >> shift[i]) & mask);
        }
        return result;
    }
    public static void main(String[] args) throws Exception {
        HOTP hotp = new HOTP("asdadas",1);
//        System.out.println(hotp.next());
        while(true){
            System.out.println(hotp.next());
            hotp.verify(hotp.next());
            Thread.sleep(1000);
        }

//        long date = new Date().getTime() / (30 * 1000);
//        Mac sha1 = Mac.getInstance("HmacSHA1");
//        SecretKeySpec secret_key = new SecretKeySpec("key".getBytes(), "HmacSHA1");
//        sha1.init(secret_key);
//        String hash = Base64.encodeBase64String(sha1.doFinal(String.valueOf(date).getBytes()));
//        System.out.println(hash);

    }
}
