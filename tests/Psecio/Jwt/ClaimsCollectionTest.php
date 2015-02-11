<?php

namespace Psecio\Jwt;

require_once "ClaimStub.php";

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
		$claim1 = new \PSecio\Jwt\Claim\Audience('test1');
		$claim2 = new \PSecio\Jwt\Claim\IssuedAt(time());
		$claim3 = new \PSecio\Jwt\Claim\Type('test3');

		$this->collection->add($claim1);
		$this->collection->add($claim2);
		$this->collection->add($claim3);

		$result = $this->collection->toArray();

		$this->assertCount(3, $result);
		$this->assertEquals($result['aud'], 'test1');
		$this->assertEquals($result['typ'], 'test3');
	}
}