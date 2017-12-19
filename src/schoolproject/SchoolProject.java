/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package schoolproject;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 *
 * @author seanb
 */
public final class SchoolProject {
    public static String ALGO = "AES";
    public static String keyValue = "LdU6_UF}?Z3Pnwa3";
    
    public static char [] convertedChar;
     
    public static String encrypt(String data) throws Exception {
        
         setKey(keyValue);
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encVal = c.doFinal(data.getBytes());
         return new BASE64Encoder().encode(encVal);
    }
    
     public static byte[] decrypt(String encryptedData) throws Exception {
        setKey(keyValue);
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, secretKey);
        c.doFinal(Base64.getDecoder().decode(encryptedData));
         byte[] convertedByte = c.doFinal(Base64.getDecoder().decode(encryptedData));
        
        return convertedByte;
    }
     
    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

       
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        
        String encryptedData;
        byte[] decryptedData;
        final char[] password = {'k','i','d','p','a','r','e','n','t','9','8','7'};
        byte [] salt = {'K','a','O','p','3','T','T','O','I','M','b','l','9','n','A','o','D','u','d','C','Q','p','C','a','E','6','z','H','j','F','p','z'};
        
      // System.out.println(encrypt("VKuX7eTC"));
    
        Properties prop = new Properties();
	InputStream input = null;

	/*try {

		input = new FileInputStream("config.properties");

		// load a properties file
		prop.load(input);
                encryptedData=prop.getProperty("ppassword");
               decryptedData= decrypt(encryptedData);
               char[] convertedChar = new char[decryptedData.length];
                for(int i=0;i < decryptedData.length;i++){
                convertedChar[i]=(char)decryptedData[i];
               }
               
               
               
               
		// get the property value and print it out
		
		

	} catch (IOException ex) {
		ex.printStackTrace();
        }*/
        
//          try {
//           SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
//           PBEKeySpec spec = new PBEKeySpec( password, salt, 3, 256 );
//           SecretKey key = skf.generateSecret( spec );
//           byte[] res = key.getEncoded( );
//           String s =  new BASE64Encoder().encode(res);
//          
//           System.out.println(s);
// 
//       } catch( NoSuchAlgorithmException | InvalidKeySpecException e ) {
//           throw new RuntimeException( e );
//       }
       
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new LoadScreen().setVisible(true);
            }
        });
    
     

    
    }
    
}
