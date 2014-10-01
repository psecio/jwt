<?php

namespace PsecioTest\Jwt\Claim;

use Psecio\Jwt\Claim\Audience;

class AudienceTest extends \PHPUnit_Framework_TestCase
{
    private $claim;

    public function setUp()
    {
        $this->claim = new Audience('test');
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
        $this->assertEquals('aud', $type);
    }
}
