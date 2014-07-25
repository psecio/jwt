<?php

namespace Psecio\Jwt;

class ClaimTest extends \PHPUnit_Framework_TestCase
{
	private $claim;
	private $value = 'test123';

	public function setUp()
	{
		$this->claim = new ClaimStub($this->value);
	}

	public function tearDown()
	{
		unset($this->claim);
	}

	/**
	 * Test that the right type is returned
	 */
	public function testGetType()
	{
		$type = $this->claim->getType();
		$this->assertEquals('stub', $type);
	}

	/**
	 * Test that the right value is returned
	 */
	public function testGetValue()
	{
		$value = $this->claim->getValue();
		$this->assertEquals($this->value, $value);
	}

	/**
	 * Test the conversion of the claim to an array
	 */
	public function testToArray()
	{
		$value = 'test-claim';
		$claim = new ClaimStub($value);

		$this->assertEquals(
			$claim->toArray(),
			array(
				'value' => $value,
				'type' => 'stub'
			)
		);
	}
}
