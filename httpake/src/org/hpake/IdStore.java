package org.hpake;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.LinkedHashSet;

/**
 * A store for HTTP request or response IDs.
 * This class is thread safe. 
 * @author Wiraj Bibile
 */
public class IdStore
{
	private final int maxSize;
	// TODO: use more concurrent data structure/reduce thread contention. 
	private final Object mutex = new Object();
	// @GuardedBy(mutex)
	private final LinkedHashSet<BigInteger> idSet;
	
	/**
	 * @param size number of Ids to remember
	 */
	public IdStore(int size)
	{
		if(size <= 0)
		{
			throw new IllegalArgumentException();
		}
		this.maxSize = size;
		idSet = new LinkedHashSet<>(size);
	}
	
	/**
	 * Copy constructor.
	 * @param original The original Id set
	 */
	public IdStore(IdStore original)
	{
		maxSize = original.maxSize;
		idSet = new LinkedHashSet<>(original.maxSize);
		idSet.addAll(original.idSet);
	}
	
	/**
	 * @return true is the store is empty
	 */
	public boolean isEmpty()
	{
		return idSet.isEmpty();
	}
	
	/**
	 * Checks whether the given Id was never seen by this store previously and remember( as being seen previously).
	 * @param id the ID to check
	 * @throws HttPakeException if the ID was used previously 
	 */
	public void checkIdAndRemember(BigInteger id) throws HttPakeException
	{
		synchronized(mutex)
		{
			if(idSet.contains(id))
			{
				throw new HttPakeException("Invalid request or response id");
			}
			Iterator<BigInteger> iter = idSet.iterator();
			
			
			if(iter.hasNext() && iter.next().compareTo(id) >= 0)
			{
				throw new HttPakeException("Invalid request or response id");
			}
			while(idSet.size() >= maxSize)
			{
				iter.remove();
				iter.next();
			}
			idSet.add(id);
		}
	}
}
