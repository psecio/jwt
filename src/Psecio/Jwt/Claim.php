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
	 * Claim "name" (ex. audience or issuer)
	 * @var string
	 */
	protected $name;

	/**
	 * Initialize the claim with the given value
	 *
	 * @param string $value Claim value
	 * @param string $type Type value [optional]
	 */
	public function __construct($value, $type = null)
	{
		$this->setValue($value);
	}

	/**
	 * Set the claim value
	 *
	 * @param string $value Claim value
	 * @return \Psecio\Jwt\Claim instance
	 * @throws \DomainException
	 */
	public function setValue($value)
	{
		if (method_exists($this, 'validate')) {
			if ($this->validate($value) == false) {
				throw new \DomainException(
					'Invalid data provided for claim "'.$this->getType().'": '.$value
				);
			}
		}
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

	/**
	 * Get the name value for the current instance
	 *
	 * @return string Name value
	 */
	public function getName()
	{
		return $this->name;
	}
}