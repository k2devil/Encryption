import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class RunnerHmac {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException{

        final String password = "MyPassword 1234";
        final String incorrectInput = "SomePassword!";

        final String correctInput = "MyPassword 1234";

        SaltedHashMac saltedHash = new SaltedHashMac();

        final String stored_hash1 = saltedHash.generateStoredForm(password);
        final String stored_hash2 = saltedHash.generateStoredForm(password);

        final String salt1 = stored_hash1.split(HmacEncryptionConstants.DELIM)[0];
        final String salt2 = stored_hash2.split(HmacEncryptionConstants.DELIM)[0];

        System.out.println(HmacEncryptionConstants.ALGO + " of '"+password+"' with salt '"+salt1+"' stores: "+stored_hash1);
        System.out.println(HmacEncryptionConstants.ALGO + " of '"+password+"' with salt '"+salt2+"' stores: "+stored_hash2);
        System.out.println("Comparing password ('"+incorrectInput+"') to ["+HmacEncryptionConstants.ALGO+HmacEncryptionConstants.DELIM+stored_hash1+"] : " + saltedHash.verifyPW(incorrectInput, stored_hash1));

        System.out.println("Comparing password ('"+correctInput+"') to ["+HmacEncryptionConstants.ALGO+HmacEncryptionConstants.DELIM+stored_hash1+"] : " + saltedHash.verifyPW(correctInput, stored_hash1));

        System.out.println("Comparing password ('"+correctInput+"') to ["+HmacEncryptionConstants.ALGO+HmacEncryptionConstants.DELIM+stored_hash2+"] : " + saltedHash.verifyPW(correctInput, stored_hash2));

    }
}
