import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SaltedHashMac {

    private static final SecretKey KEY = new SecretKeySpec( HmacEncryptionConstants.SYSTEMPASSWORD.getBytes(),HmacEncryptionConstants.ALGO);

    private static byte[] generateSalt(){

        UUID uuid = UUID.randomUUID();
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);

        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());
        return bb.array();
    }

    public String generateStoredForm(String password) throws NoSuchAlgorithmException, InvalidKeyException{

        byte[] salt = generateSalt();
        byte[] plaintext = HELPER_concat_plaintext(salt,password.getBytes());

        return Base64.getEncoder().encodeToString(salt)+ HmacEncryptionConstants.DELIM + Base64.getEncoder().encodeToString(generateHash(plaintext));
    }
    
    private static byte[] generateHash(byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac md = Mac.getInstance(HmacEncryptionConstants.ALGO);
        md.init(KEY);
        md.update(plaintext);
        return md.doFinal();
    }

    public boolean verifyPW(String providePassword, String storedHash) throws NoSuchAlgorithmException, InvalidKeyException{
        byte[] reclaimed_salt = Base64.getDecoder().decode(storedHash.split(HmacEncryptionConstants.DELIM)[0]);
        byte[] reclaimed_cipheredText = Base64.getDecoder().decode(storedHash.split(HmacEncryptionConstants.DELIM)[1]);

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
