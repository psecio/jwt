<?php

namespace Psecio\Jwt;

require "ClaimStub.php";

class ClaimsCollectionTest extends \PHPUnit_Framework_TestCase
{
    private $collection;

    public function setUp()
    {
        $this->collection = new ClaimsCollection();
    }
    public function tearDown()
    {
        unset($this->collection);
    }

    /**
     * Add a single claim to the collection
     */
    public function testAddSingleClaim()
    {
        $claim = new \PSecio\Jwt\ClaimStub('test1');
        $this->collection->add($claim);
        $result = $this->collection->toArray();

        $this->assertCount(1, $result);
        $this->assertEquals($result['stub'], 'test1');
    }

    /**
     * Add a multiple claims to the collection
     */
    public function testAddMultipleClaim()
    {
        $claim1 = new \PSecio\Jwt\ClaimStub('test1', 'claim1');
        $claim2 = new \PSecio\Jwt\ClaimStub('test2', 'claim2');
        $claim3 = new \PSecio\Jwt\ClaimStub('test3', 'claim3');

        $this->collection->add($claim1);
        $this->collection->add($claim2);
        $this->collection->add($claim3);

        $result = $this->collection->toArray();

        $this->assertCount(3, $result);
        $this->assertEquals($result['claim1'], 'test1');
        $this->assertEquals($result['claim3'], 'test3');
    }
}
