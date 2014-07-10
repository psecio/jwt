<?php

namespace Psecio\Jwt;

abstract class Claim
{
	/**
	 * Claim type
	 * @var string
	 */
	protected $type;

	/**
	 * Claim value
	 * @var string
	 */
	protected $value;

	/**
	 * Initialize the claim with the given value
	 *
	 * @param string $value Claim value
	 */
	public function __construct($value)
	{
		$this->setValue($value);
	}

	/**
	 * Set the claim value
	 *
	 * @param string $value Claim value
	 * @return \Psecio\Jwt\Claims instance
	 */
	public function setValue($value)
	{
		$this->value = $value;
		return $this;
	}

	/**
	 * Get the current value
	 *
	 * @return string Claim value
	 */
	public function getValue()
	{
		return $this->value;
	}

	/**
	 * Set the claim type
	 *
	 * @param string $type Claim type
	 * @return \Psecio\Jwt\Claims instance
	 */
	public function setType($type)
	{
		$this->type = $type;
		return $this;
	}

	/**
	 * Get the current claim type
	 *
	 * @return string Claim type
	 */
	public function getType()
	{
		return $this->type;
	}

	/**
	 * Transform claim data into an array
	 *
	 * @return array Claim data
	 */
	public function toArray()
	{
		return array(
			'value' => $this->getValue(),
			'type' => $this->getType()
		);
	}
}