/**
 * Created by rc452 on 2017/3/5.
 */
public class Application {
    public static void main(String[] args) throws Exception {
        HOTP hotp = new HOTP("asdadas",1);
        for (int i =0;i < 60;i++){
            System.out.println(hotp.next());
            hotp.verify(hotp.next());
            Thread.sleep(1000);
        }
    }
}
