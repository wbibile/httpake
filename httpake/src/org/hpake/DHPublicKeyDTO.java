package org.hpake;

import static org.hpake.Utils.decodeBase64Unsigned;
import static org.hpake.Utils.encodeBase64;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey;
import org.hpake.protocol.Headers;

/**
 * Represents the data format of the {@link Headers#PUBLIC_KEY} response header.
 * This data transfer objects encapsulates a Diffie-Hellmen public key.
 * @author Wiraj Bibile  
 */
public class DHPublicKeyDTO
{
	
	/**
	 * The large prime modulus used used by the exchange.
	 */
	public final BigInteger p;
	
	/**
	 * The selected generator (generator of units of p). 
	 */
	public final BigInteger g;
	
	/**
	 * The public value 'y',  where y = (g^s)%p (where 's' is the secret value).
	 */
	public final BigInteger y;
	
	/**
	 * Constructs an instance from a {@link Headers#PUBLIC_KEY} response header value.
	 * @param stringValue server header value
	 * @return a new DHPublicKeyDTO
	 * @throws HttPakeException if the input string format is invalid
	 */
	public static DHPublicKeyDTO fromSerializationString(String stringValue) throws HttPakeException
	{
		String[] parts = Utils.VALUE_SEPARATOR_PATTERN.split(stringValue);
		if(parts.length != 3)
		{
			throw new HttPakeException("Unable to parse input public key.");
		}
		BigInteger p = decodeBase64Unsigned(parts[0]);
		BigInteger g = decodeBase64Unsigned(parts[1]);
		BigInteger y = decodeBase64Unsigned(parts[2]);
		return new DHPublicKeyDTO(p,g,y);
	}
	
	/**
	 * Construct an instance from constituent parts.
	 * @param p prime modulus 
	 * @param g generator of units of p 
	 * @param y The public value
	 */
	public DHPublicKeyDTO(BigInteger p, BigInteger g, BigInteger y)
	{
		this.p = p;
		this.g = g;
		this.y = y;
	}
	
	/**
	 * Constructs instance from {@link BCDHPublicKey} 
	 * @param publicKey the public key
	 */
	public DHPublicKeyDTO(BCDHPublicKey publicKey)
	{
		DHParameterSpec params = publicKey.getParams();
		p = params.getP();
		g = params.getG();
		y = publicKey.getY();
	}
	
	/**
	 * Derive an instance that uses a new y public value,
	 * while p (prime modulus) and g (generator) remains the same.
	 * @param newYValue the new y value
	 * @return the derived instance
	 */
	public DHPublicKeyDTO derive(BigInteger newYValue)
	{
		return new DHPublicKeyDTO(p, g, newYValue);
	}
	
	public String  getSerializationString()
	{
		return encodeBase64(p)+Utils.VALUE_SEPARATOR+encodeBase64(g)+Utils.VALUE_SEPARATOR+encodeBase64(y);
	}
	
	
	public PublicKey getPublicKey() throws HttPakeException
	{
		DHPublicKeySpec spec = new DHPublicKeySpec(y, p, g);
		try 
		{
			return KeyFactory.getInstance("DH", "BC").generatePublic(spec);
		}
		catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) 
		{
			throw new HttPakeException("Unable to parse public key.", e);
		}
	}
	

}