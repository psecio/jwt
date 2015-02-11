<?php

namespace Psecio\Jwt;

class ClaimsCollection implements \Countable, \Iterator
{
	/**
	 * Set of Claims
	 * @var \Psecio\Jwt\Claim[]
	 */
	private $claims = array();

	/**
	 * Add a claim to the collection
	 *
	 * @param \Psecio\Jwt\Claim $claim Claim instance
	 * @return \Psecio\Jwt\ClaimsCollection instance
	 */
	public function add(\Psecio\Jwt\Claim $claim)
	{
		$this->claims[] = $claim;
		return $this;
	}

	/**
	 * Convert the collection to a nested array
	 *
	 * @return array Contents of the collection
	 */
	public function toArray()
	{
		$data = array();
		foreach ($this->claims as $claim) {
			$data[$claim->getType()] = $claim->getValue();
		}
		return $data;
	}

	/**
     * Current position in data (used in Iterator)
     * @var integer
     */
    private $position = 0;

    // For Countable interface
    /**
     * Return a count of the current data
     *
     * @return integer Count result
     */
    public function count()
    {
        return count($this->claims);
    }

    // For Iterator
    /**
     * Return the current item in the set
     *
     * @return mixed Current data item
     */
    public function current()
    {
        return $this->claims[$this->position];
    }

    /**
     * Return the current key (position) value
     *
     * @return integer Position value
     */
    public function key()
    {
        return $this->position;
    }

    /**
     * Get the next position value
     *
     * @return integer Next position
     */
    public function next()
    {
        return ++$this->position;
    }

    /**
     * Rewind to the beginning of the set (position = 0)
     */
    public function rewind()
    {
        $this->position = 0;
    }

    /**
     * See if the requested position exists in the data
     *
     * @return boolean Exists/doesn't exist
     */
    public function valid()
    {
        return isset($this->claims[$this->position]);
    }
}