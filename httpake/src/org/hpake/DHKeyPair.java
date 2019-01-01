package org.hpake;

import java.security.PrivateKey;

import org.bouncycastle.jcajce.provider.asymmetric.dh.BCDHPublicKey;

/**
 * Container for a Diffie-Hellmen key pair. 
 * @author WIraj Bibile
 */
public class DHKeyPair 
{
	private final PrivateKey privateKey;
	private final BCDHPublicKey publicKey;

	public DHKeyPair(BCDHPublicKey publicKey, PrivateKey privateKey)
	{
		this.publicKey = publicKey;
		this.privateKey = privateKey;
				
	}

	/**
	 * @return The private key.
	 */
	public PrivateKey getPrivateKey()
	{
		return privateKey;
	}

	/**
	 * @return The public key
	 */
	public BCDHPublicKey getPublicKey() 
	{
		return publicKey;
	}
}
