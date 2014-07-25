<?php

namespace Psecio\Jwt\Claim;

class JwtIdTest extends \PHPUnit_Framework_TestCase
{
	private $claim;

	public function setUp()
	{
		$this->claim = new JwtId('test');
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
		$this->assertEquals('jti', $type);
	}
}