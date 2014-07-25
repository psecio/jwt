<?php

namespace Psecio\Jwt\Claim;

class NotBeforeTest extends \PHPUnit_Framework_TestCase
{
    private $claim;

    public function setUp()
    {
        $this->claim = new NotBefore(time());
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
        $this->assertEquals('nbf', $type);
    }

    /**
     * Test that an exception is thrown when bad, non-numeric
     *     data is given on init
     *
     * @expectedException \DomainException
     */
    public function testInvalidData()
    {
        $claim = new NotBefore('bad-data');
    }
}