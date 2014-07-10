<?php

namespace Psecio\Jwt;

class ClaimsCollection
{
	private $claims = array();

	public function add(\Psecio\Jwt\Claims $claim)
	{
		$this->claims[] = $claim;
		return $this;
	}

	public function toArray()
	{
		$data = array();
		foreach ($this->claims as $claim) {
			$data[$claim->getType()] = $claim->getValue();
		}
		return $data;
	}
}