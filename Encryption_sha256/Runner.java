import java.security.NoSuchAlgorithmException;

public class Runner {
    public static void main(String[] args) throws NoSuchAlgorithmException{

        final String password = "MyPassword 1234";
        final String incorrectInput = "SomePassword!";

        final String correctInput = "MyPassword 1234";

        SaltedHash saltedHash = new SaltedHash();

        final String stored_hash1 = saltedHash.generateStoredForm(password);
        final String stored_hash2 = saltedHash.generateStoredForm(password);

        final String salt1 = stored_hash1.split(EncryptionConstants.DELIM)[0];
        final String salt2 = stored_hash2.split(EncryptionConstants.DELIM)[0];

        System.out.println(EncryptionConstants.ALGO + " of '"+password+"' with salt '"+salt1+"' stores: "+stored_hash1);
        System.out.println(EncryptionConstants.ALGO + " of '"+password+"' with salt '"+salt2+"' stores: "+stored_hash2);
        System.out.println("Comparing password ('"+incorrectInput+"') to ["+EncryptionConstants.ALGO+EncryptionConstants.DELIM+stored_hash1+"] : " + saltedHash.verifyPW(incorrectInput, stored_hash1));

        System.out.println("Comparing password ('"+correctInput+"') to ["+EncryptionConstants.ALGO+EncryptionConstants.DELIM+stored_hash1+"] : " + saltedHash.verifyPW(correctInput, stored_hash1));

        System.out.println("Comparing password ('"+correctInput+"') to ["+EncryptionConstants.ALGO+EncryptionConstants.DELIM+stored_hash2+"] : " + saltedHash.verifyPW(correctInput, stored_hash2));

    }
}
