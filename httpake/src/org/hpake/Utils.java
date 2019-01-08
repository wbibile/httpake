package org.hpake;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.UUID;
import java.util.regex.Pattern;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;

/**
 * Contains utility methods.
 * @author Wiraj Bibile
 */
public class Utils
{
	public static final String VALUE_SEPARATOR = "_";
	public static final Pattern VALUE_SEPARATOR_PATTERN = Pattern.compile(VALUE_SEPARATOR); 
	public static final String UTF_8_CHARSET = "UTF-8";
	
	/**
	 * Generates a UUID.
	 * @return the UUID 
	 */
	public static String generateUUID()
	{
		return UUID.randomUUID().toString();
	}
	
	/**
	 * Generates a nonce.
	 * @return the nonce
	 */
	public static String generateNonce()
	{
		// TODO: Use of UUID not a good nonce. Use a PRNG 
		return generateUUID();
	}
	
	/**
	 * Base64 encodes the big-endian bytes of the given integer.  
	 * @param value integer to be encoded 
	 * @return the base64 encoded string
	 */
	public static String encodeBase64(BigInteger value)
	{
		return encodeBase64(value.toByteArray());
	}
	
	
	/**
	 * Base64 encodes the given byte array
	 * @param value the input byte array
	 * @return the base 64 encoded string
	 */
	private static String encodeBase64(byte[] value)
	{
		return Base64.toBase64String(value);
	}
	
	/**
	 * Decodes the given base64 string to big-endian bytes interpreted as an unsigned integer.  
	 * @param base64String the input string
	 * @return the resultant integer
	 * @throws HttPakeException if the string could not be decoded
	 */
	public static BigInteger decodeBase64Unsigned(String base64String) throws HttPakeException
	{
		try
		{
			
			byte[] bytes = Base64.decode(base64String);
			if(bytes.length >= 1 && (bytes[0]&0x80) == 0x80)
			{
				byte[] newBytes = new byte[bytes.length+1];
				System.arraycopy(bytes, 0, newBytes, 1, bytes.length);
				bytes = newBytes;
			}
			return new BigInteger(bytes);
		}
		catch(IllegalArgumentException e)
		{
			throw new HttPakeException("Could not decode base64 string", e);
		}
	}
	
	/**
	 * Derive key from the DH shared secret and passwordorHash. 
	 * @param passwordOrHash the users password or hash
	 * @param dhSecret The DH shared secret 
	 * @return The derived key
	 */
	public static byte[] deriveKey(byte[] passwordOrHash, byte[] dhSecret) throws HttPakeException
	{
		return hmacSha256(passwordOrHash, dhSecret);
	}
	
	/**
	 * Signs the given String. The Text is signed by converting the text into UTF-8 bytes and, signing the bytes using HMAC-SHA256.
	 * @param key The HMAC signing key
	 * @param str the string to sign
	 * @return the HMAC signature bytes as a base64 encoded string
	 */
	public static String signText(byte[] key, String str) throws HttPakeException
	{
		return encodeBase64(hmacSha256(key, getUtf8Bytes(str)));
	}
	
	private static byte[] hmacSha256(byte[] key, byte[] data)
	{
		HMac hmac = new HMac(new SHA256Digest());
		hmac.init(new KeyParameter(key));
		hmac.update(data, 0, data.length);
		byte[] result = new byte[32];
		hmac.doFinal(result, 0);
		return result;
	}
	
	/**
	 * Computes the SHA256 digest of the given message. 
	 * @param message The input message to compute the digest of
	 * @return The digest
	 */
	public static byte[] getSha256Digest(byte[] message)
	{
		SHA256Digest digest = new SHA256Digest();
		digest.update(message, 0, message.length);
		byte[] result = new byte[256];
		digest.doFinal(result, 0);
		return result;
	}
	
	/**
	 * Computes the UTF-8 bytes of the given String.
	 * @param str The input string to compute the bytes from 
	 * @return The UTF-8 bytes
	 * @throws HttPakeException If the system does not recognize UTF-8 
	 */
	public static byte[] getUtf8Bytes(String str) throws HttPakeException
	{
		try 
		{
			return str.getBytes(UTF_8_CHARSET);
		}
		catch (UnsupportedEncodingException e) 
		{
			throw new HttPakeException(UTF_8_CHARSET+" not supported", e).setAsServerError();
		}
	}
}
