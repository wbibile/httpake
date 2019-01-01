package org.hpake;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey;

/**
 * Contains Diffie-Hellmen utility methods.
 * @author Wiraj Bibile
 */
public class DHUtils
{
	
	/**
	 * Generate a new Diffie-Hellmen key pair.
	 * @return the newly generated keypair
	 */
	public static DHKeyPair generateKeyPair() throws HttPakeException
	{
		try
		{
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
			paramGen.init(2048);

			AlgorithmParameters params = paramGen.generateParameters();
			DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
			keyGen.initialize(dhSpec, new SecureRandom());
			KeyPair keyPair = keyGen.generateKeyPair();
			return new DHKeyPair((BCDHPublicKey) keyPair.getPublic(), keyPair.getPrivate());
		} 
		catch (NoSuchAlgorithmException | InvalidParameterSpecException | NoSuchProviderException| InvalidAlgorithmParameterException e)
		{
			throw new HttPakeException("Error generating DH key pair.", e).setAsServerError();
		}
	}
	
	/**
	 * Generate a new key pair using the given public prime modulus and, generator. 
	 * @param pValue The prime modulus
	 * @param gValue The generator
	 * @return key pair consisting of the 
	 */
	public static DHKeyPair generateKeyPair(BigInteger pValue, BigInteger gValue) throws HttPakeException
	{
		try 
		{
			DHParameterSpec dhParams = new DHParameterSpec(pValue, gValue);
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
			keyGen.initialize(dhParams, new SecureRandom());
			KeyPair keyPair = keyGen.generateKeyPair();
			return new DHKeyPair((BCDHPublicKey) keyPair.getPublic(), keyPair.getPrivate());
		} 
		catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e)
		{
			throw new HttPakeException(e);
		}
	}
	
	/**
	 * Establish the Diffie-Hellmen shared secrete.
	 * @param dhPrivateKey the DH public key
	 * @param dhPublicKey the DH private key
	 * @return The shared secret 
	 */
	public static byte[] dhSecret(Key dhPrivateKey, Key dhPublicKey) throws HttPakeException 
	{
		try 
		{
			KeyAgreement agreement = KeyAgreement.getInstance("DH", "BC");
			agreement.init(dhPrivateKey);
			agreement.doPhase(dhPublicKey, true);
			return agreement.generateSecret();
		} 
		catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | IllegalStateException e) 
		{
			throw new HttPakeException(e);
		}
	}
}
