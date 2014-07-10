<?php

namespace Psecio\Jwt;

abstract class Claims
{
	protected $type;
	protected $value;

	public function __construct($value)
	{
		$this->setValue($value);
	}
	public function setValue($value)
	{
		$this->value = $value;
		return $this;
	}
	public function getValue()
	{
		return $this->value;
	}
	public function setType($type)
	{
		$this->type = $type;
		return $this;
	}
	public function getType()
	{
		return $this->type;
	}

	public function toArray()
	{
		return array(
			'value' => $this->getValue(),
			'type' => $this->getType()
		);
	}
}