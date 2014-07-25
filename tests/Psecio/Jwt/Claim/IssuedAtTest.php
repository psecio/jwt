<?php

namespace Psecio\Jwt\Claim;

class IssuedAtTest extends \PHPUnit_Framework_TestCase
{
	private $claim;

	public function setUp()
	{
		$this->claim = new IssuedAt(time());
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
		$this->assertEquals('iat', $type);
	}

	/**
     * Test that an exception is thrown when bad, non-numeric
     *     data is given on init
     *
     * @expectedException \DomainException
     */
    public function testInvalidData()
    {
        $claim = new IssuedAt('bad-data');
    }
}