<?php

namespace Psecio\Jwt;

class ClaimsCollection
{
	/**
	 * Set of Claims
	 * @var array
	 */
	private $claims = array();

	/**
	 * Add a claim to the collection
	 *
	 * @param \Psecio\Jwt\Claims $claim Claim instance
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
}