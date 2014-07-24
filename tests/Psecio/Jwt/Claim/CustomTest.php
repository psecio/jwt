<?php

namespace Psecio\Jwt\Claim;

class CustomTest extends \PHPUnit_Framework_TestCase
{
    private $claim;

    public function setUp()
    {
        $this->claim = new Custom('test', 'tst');
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
        $this->assertEquals('tst', $type);
    }
}