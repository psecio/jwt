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
		$type = $this->claim->getType();
		$this->assertEquals('test123', $this->value);
	}
}