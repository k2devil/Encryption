import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

public class SaltedHash {

    private static byte[] generateSalt(){

        UUID uuid = UUID.randomUUID();
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);

        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return bb.array();
    }

    public String generateStoredForm(String password) throws NoSuchAlgorithmException{

        byte[] salt = generateSalt();
        byte[] plaintext = HELPER_concat_plaintext(salt,password.getBytes());

        return Base64.getEncoder().encodeToString(salt) + EncryptionConstants.DELIM + Base64.getEncoder().encodeToString(generateHash(plaintext));
    }
    
    private static byte[] generateHash(byte[] plaintext) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(EncryptionConstants.ALGO);
        md.update(plaintext);
        return md.digest();
    }

    public boolean verifyPW(String providePassword, String storedHash) throws NoSuchAlgorithmException{
        byte[] reclaimed_salt = Base64.getDecoder().decode(storedHash.split(EncryptionConstants.DELIM)[0]);
        byte[] reclaimed_cipheredText = Base64.getDecoder().decode(storedHash.split(EncryptionConstants.DELIM)[1]);

        byte[] providedHash = generateHash(HELPER_concat_plaintext(reclaimed_salt, providePassword.getBytes()));

        if(Arrays.equals(providedHash, reclaimed_cipheredText)) {
            return true;
        }
        return false;
    }

    private static byte[] HELPER_concat_plaintext(byte[] salt, byte[] password) {
        // TODO Auto-generated method stub
        byte[] result = new byte[salt.length+ password.length];
        int z=0;
        for(int i=0;i<salt.length;i++){
            result[z] = salt[i];
            z++;
        }
        for(int i=0;i<password.length;i++){
            result[z] = salt[i];
            z++;
        }
        return result;
    }
}
