import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import com.itextpdf.text.pdf.crypto.ARCFOUREncryption;
// Algorithm 2.A => : Retrieving the file encryption key from an encrypted
// document in order to decrypt it.
// Also hashing algo 2.B
public class FileDecryptionAlgorithm {


    static byte[] p = {  (byte)0x28, (byte) 0xBF, (byte)0x4E, (byte)0x5E, (byte)0x4E, (byte)0x75,
            (byte) 0x8A, (byte)0x41, (byte)0x64, (byte)0x00, (byte)0x4E, (byte)0x56, (byte) 0xFF,
            (byte) 0xFA, (byte)0x01, (byte)0x08, (byte)0x2E, (byte)0x2E, (byte)0x00, (byte) 0xB6,
            (byte) 0xD0, (byte)0x68, (byte)0x3E, (byte) 0x80, (byte)0x2F, (byte)0x0C, (byte) 0xA9,
            (byte) 0xFE, (byte)0x64, (byte)0x53, (byte)0x69, (byte)0x7A  };
    static byte[] permsStringFinal;
    static byte[] finalEncryptionKey;
    /***  General Methods and Algo 2A and 2B ***/
    public static byte[] retrieveFileEncryptionKey(byte[] userPasswordBytes, byte[] ownerPasswordBytes,
                                                   byte[] ownerValidationSalt, byte[] ownerKeySalt, byte[] uString
                                                  ) throws Exception
    {

        // Step a: Generate UTF-8 password from Unicode input
        byte[] utf8UserPassword = generateUTF8Password(userPasswordBytes);
        byte[] utf8OwnerPassword = generateUTF8Password(ownerPasswordBytes);
        // Step c: Test the password against the owner key
        boolean isOwnerPassword = testOwnerPassword(utf8OwnerPassword, ownerValidationSalt, uString);
        System.out.println("Is Owner Password -"+ isOwnerPassword);
        // Step d: Compute the intermediate owner key
        byte[] ownerKey = computeIntermediateOwnerKey(utf8OwnerPassword, ownerKeySalt, uString);
        // Step e: Compute the intermediate user key
        byte[] userKey = computeIntermediateUserKey(utf8UserPassword, uString);

        return ownerKey;
    }

    private static byte[] generateUTF8Password(byte[] input) {
        // Step a: Convert input to UTF-8 representation
        String utf8String = new String(input, StandardCharsets.UTF_8);

        // Step b: Truncate to 127 bytes if longer
        if (utf8String.length() > 127) {
            utf8String = utf8String.substring(0, 127);
        }

        return utf8String.getBytes(StandardCharsets.UTF_8);
    }

    private static boolean testOwnerPassword(byte[] password, byte[] ownerValidationSalt, byte[] uString) throws Exception {
        byte[] input = concatenateBytes(password, ownerValidationSalt, uString);
        byte[] hash = computeHash(input,uString);
        byte[] oStringPrefix = Arrays.copyOfRange(hash, 0, 32);
        byte[] oString = Arrays.copyOfRange(generateOKey(password,uString), 0, 48);
        return Arrays.equals(oStringPrefix, oString);
    }

    private static byte[] computeIntermediateOwnerKey(byte[] ownerPassword, byte[] ownerKeySalt, byte[] uString) throws Exception {
        byte[] input = concatenateBytes(ownerPassword, ownerKeySalt, uString);
        byte[] hash =  computeHash(input,uString);
        byte[] intermediateKey = Arrays.copyOfRange(hash, 0, 32);
        return intermediateKey;
    }

    private static byte[] computeIntermediateUserKey(byte[] userPassword, byte[] uString) throws Exception {
        byte[] input = concatenateBytes(userPassword, Arrays.copyOfRange(uString, 32, 40));
        byte[] intermediateKey = computeHash(input,uString);
        return intermediateKey;
    }

    private static byte[] decryptPermsString(byte[] permsString, byte[] fileEncryptionKey) throws Exception {
        return decryptAES256ECB(permsString, fileEncryptionKey);
    }

    private static boolean verifyPermsString(byte[] permsDecrypted) {
        // Verify that bytes 9-11 of the result are the characters "a", "d", "b"
        if (permsDecrypted.length >= 12) {
            return permsDecrypted[8] == 'a' && permsDecrypted[9] == 'd' && permsDecrypted[10] == 'b';
        }
        return false;
    }

    private static byte[] concatenateBytes(byte[]... arrays) {
        int totalLength = Arrays.stream(arrays).mapToInt(arr -> arr.length).sum();
        byte[] result = new byte[totalLength];
        int currentIndex = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, currentIndex, array.length);
            currentIndex += array.length;
        }
        return result;
    }

    private static byte[] computeHash(byte[] input, byte[] uString) throws Exception {
        // Step 1: Take the SHA-256 hash of the original input
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] k = sha256.digest(input);

        // Step 2: Perform the following steps (a)-(d) 64 times
        for (int round = 0; round < 64; round++) {
            byte[] k1 = concatenateBytes(input, k, Arrays.copyOfRange(uString, 0, 48));

            // Step 2b: Encrypt K1 with AES-128 (CBC, no padding)
            byte[] aesKey = Arrays.copyOfRange(k, 0, 16);
            byte[] aesIV = Arrays.copyOfRange(k, 16, 32);
            byte[] e = encryptAES128CBC(k1, aesKey, aesIV);

            // Step 2c: Determine the hash algorithm to use
            int moduloResult = e[0] & 0xFF % 3;
            String hashAlgorithm;
            switch (moduloResult) {
                case 0:
                    hashAlgorithm = "SHA-256";
                    break;
                case 1:
                    hashAlgorithm = "SHA-384";
                    break;
                case 2:
                    hashAlgorithm = "SHA-512";
                    break;
                default:
                    throw new Exception("Invalid modulo result");
            }

            // Step 2d: Take the hash of E using the determined algorithm
            MessageDigest hashAlgorithmDigest = MessageDigest.getInstance(hashAlgorithm);
            k = hashAlgorithmDigest.digest(e);
        }

        // Step 3: Return the first 32 bytes of the final K
        return Arrays.copyOfRange(k, 0, 32);
    }

    static byte[] encryptAES128CBC(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(plaintext);
    }

    private static byte[] decryptAES256CBC(byte[] ciphertext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(ciphertext);
    }

    private static byte[] decryptAES256ECB(byte[] ciphertext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return cipher.doFinal(ciphertext);
    }

    /***   Algorithm 8 Implementation         ***/
    public static byte[] generateUKey(byte[] userPassword) throws Exception {
        // Step a: Generate User Validation Salt and User Key Salt
        SecureRandom secureRandom = new SecureRandom();
        byte[] userValidationSalt = new byte[8];
        byte[] userKeySalt = new byte[8];
        secureRandom.nextBytes(userValidationSalt);
        secureRandom.nextBytes(userKeySalt);

        // Step a contd.: Compute the 32-byte hash for U key
        byte[] uKeyInput = concatenateBytes(generateUTF8Password(userPassword), userValidationSalt);
        byte[] uKeyHash = computeHash(uKeyInput);

        // Combine the hash with salts
        byte[] uKey = concatenateBytes(uKeyHash, userValidationSalt, userKeySalt);

        return uKey;
    }

    public static byte[] generateUEKey(byte[] userPassword) throws Exception {
        // Step b: Compute the 32-byte hash for UE key
        SecureRandom secureRandom = new SecureRandom();
        byte[] userKeySalt = new byte[8];
        secureRandom.nextBytes(userKeySalt);
        byte[] ueKeyInput = concatenateBytes(generateUTF8Password(userPassword), userKeySalt); // User Key Salt is not used here
        byte[] ueKeyHash = computeHash(ueKeyInput);

        // Encrypt the file encryption key using AES-256
        byte[] fileEncryptionKey = new byte[32];
        byte[] ueKey = encryptAES256CBC(fileEncryptionKey, ueKeyHash);

        return ueKey;
    }
    private static byte[] computeHash(byte[] input) throws Exception {
        // Use the hashing algorithm from Algorithm 2.B
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] k = sha256.digest(input);

        for (int round = 0; round < 64; round++) {
            byte[] k1 = concatenateBytes(input, k, new byte[48]);

            byte[] aesKey = Arrays.copyOfRange(k, 0, 16);
            byte[] aesIV = Arrays.copyOfRange(k, 16, 32);
            byte[] e = encryptAES128CBC(k1, aesKey, aesIV);

            int moduloResult = e[0] & 0xFF % 3;
            String hashAlgorithm;
            switch (moduloResult) {
                case 0:
                    hashAlgorithm = "SHA-256";
                    break;
                case 1:
                    hashAlgorithm = "SHA-384";
                    break;
                case 2:
                    hashAlgorithm = "SHA-512";
                    break;
                default:
                    throw new Exception("Invalid modulo result");
            }

            MessageDigest hashAlgorithmDigest = MessageDigest.getInstance(hashAlgorithm);
            k = hashAlgorithmDigest.digest(e);
        }

        return Arrays.copyOfRange(k, 0, 32);
    }

    private static byte[] encryptAES256CBC(byte[] plaintext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
        return cipher.doFinal(plaintext);
    }

    /***   Algorithm 9 Implementation         ***/
    public static byte[] generateOKey(byte[] ownerPassword, byte[] uString) throws Exception {
        // Step a: Generate Owner Validation Salt and Owner Key Salt
        SecureRandom secureRandom = new SecureRandom();
        byte[] ownerValidationSalt = new byte[8];
        byte[] ownerKeySalt = new byte[8];
        secureRandom.nextBytes(ownerValidationSalt);
        secureRandom.nextBytes(ownerKeySalt);

        // Step a contd.: Compute the 32-byte hash for O key
        byte[] oKeyInput = concatenateBytes(generateUTF8Password(ownerPassword), ownerValidationSalt, uString);
        byte[] oKeyHash = computeHash(oKeyInput);

        // Combine the hash with salts
        byte[] oKey = concatenateBytes(oKeyHash, ownerValidationSalt, ownerKeySalt);

        return oKey;
    }

    public static byte[] generateOEKey(byte[] ownerPassword, byte[] uString) throws Exception {
        // Step b: Compute the 32-byte hash for OE key
        byte[] oeKeyInput = concatenateBytes(generateUTF8Password(ownerPassword), new byte[8], uString); // Owner Key Salt is not used here
        byte[] oeKeyHash = computeHash(oeKeyInput);

        // Encrypt the file encryption key using AES-256
        byte[] fileEncryptionKey = new byte[32];;
        byte[] oeKey = encryptAES256CBC(fileEncryptionKey, oeKeyHash);

        return oeKey;
    }

    /***   Algorithm 10 Implementation         ***/
    public static byte[] generatePermsString(int permissions, boolean encryptMetadata, byte[] fileEncryptionKey) throws Exception {
        byte[] permsBlock = new byte[16];

        // Step a: Extend permissions to 64 bits
        long extendedPermissions = ((long) permissions) & 0xFFFFFFFFL;

        // Step b: Record the 8 bytes of permissions
        for (int i = 0; i < 8; i++) {
            permsBlock[i] = (byte) (extendedPermissions & 0xFF);
            extendedPermissions >>= 8;
        }
        // Step c: Set byte 8 to "T" or "F" based on EncryptMetadata
        permsBlock[8] = encryptMetadata ? (byte) 'T' : (byte) 'F';
        // Step d: Set bytes 9-11 to "a", "d", "b"
        permsBlock[9] = (byte) 'a';
        permsBlock[10] = (byte) 'd';
        permsBlock[11] = (byte) 'b';
        // Step e: Set bytes 12-15 to random data
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(Arrays.copyOfRange(permsBlock, 12, 16));
        // Step f: Encrypt the 16-byte block using AES-256 in ECB mode
        byte[] permsString = encryptAES256ECB(permsBlock, fileEncryptionKey);
        return permsString;
    }
    private static byte[] encryptAES256ECB(byte[] plaintext, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return cipher.doFinal(plaintext);
    }

    /***   Algorithm 11 Implementation         ***/
    public static boolean authenticateUserPassword(byte[] userPassword, byte[] userValidationSalt, byte[] uString) throws Exception {
        // Compute the 32-byte hash for user key authentication
        byte[] userKeyInput = concatenateBytes(generateUTF8Password(userPassword), userValidationSalt);
        byte[] userKeyHash = computeHash(userKeyInput);

        // Check if the computed hash matches the first 32 bytes of the U string
        return Arrays.equals(Arrays.copyOfRange(userKeyHash, 0, 32), Arrays.copyOfRange(uString, 0, 32));
    }

    public static void main(String[] args) throws Exception {
        // Example usage
        // Create a secure random number generator
        SecureRandom random = new SecureRandom();
        // Define the length of the salt (8 bytes in this case)
        int saltLength = 8;

        byte[] userPassword = "hasdiaiwe78345".getBytes(StandardCharsets.UTF_8);
        byte[] ownerPassword = "saayei7878345".getBytes(StandardCharsets.UTF_8);

        // Create arrays to store the salt values
        byte[] ownerValidationSalt = new byte[saltLength];
        byte[] userValidationSalt = new byte[saltLength];
        // Generate random values for ownerValidationSalt and userValidationSalt
        random.nextBytes(ownerValidationSalt);
        random.nextBytes(userValidationSalt);

        byte[] ownerKeySalt = new byte[8];
        byte[] uString = generateUKey(userPassword);
//        byte[] oeString = generateOEKey(ownerPassword,uString);
//        byte[] ueString = generateUEKey(userPassword) ;


        // Example usage
        int permissions = 0x12345678; // Replace with the desired permissions value
        boolean encryptMetadata = true; // Replace with true or false


        try {
            byte[] fileEncryptionKey = retrieveFileEncryptionKey(userPassword, ownerPassword,
                    ownerValidationSalt, ownerKeySalt, uString);
            finalEncryptionKey = fileEncryptionKey;
            permsStringFinal = generatePermsString(permissions,encryptMetadata,fileEncryptionKey);

                   byte[] permsDecrypted = decryptPermsString(permsStringFinal, fileEncryptionKey);
                   System.out.println( "Decrypted Perms Array => " +  Arrays.toString(permsDecrypted));
           System.out.println("File Encryption Key: " + Arrays.toString(fileEncryptionKey));


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
