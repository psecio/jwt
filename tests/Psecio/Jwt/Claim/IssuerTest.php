<?php

namespace Psecio\Jwt\Claim;

class IssuerTest extends \PHPUnit_Framework_TestCase
{
	private $claim;

	public function setUp()
	{
		$this->claim = new Issuer('test');
	}

	public function tearDown()
	{
		unset($this->claim);
	}

	/**
	 * Test that the right type is returned for Audience
	 */
	public function testGetType()
	{
		$type = $this->claim->getType();
		$this->assertEquals('iss', $type);
	}
}