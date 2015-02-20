<?php

namespace Psecio\Jwt;

class HeaderTest extends \PHPUnit_Framework_TestCase
{
	private $header;

	public function setUp()
	{
		$key = 'foobarbaz';
		$this->header = new Header($key);
	}
	public function tearDown()
	{
		unset($this->header);
	}

	/**
	 * Data provider for JWT algorithm hash to real hash string
	 */
	public function AlgorithmDataProvider()
	{
		return array(
			array('HS256', 'SHA256'),
			array('HS384', 'SHA384'),
			array('HS512', 'SHA512')
		);
	}

	/**
	 * Test the getter/setter for the key value
	 */
	public function testGetSetKey()
	{
		$key = 'test123';

		$this->header->setKey($key);
		$this->assertEquals($key, $this->header->getKey());
	}

	/**
	 * Test that the right hash resolution is returned
	 *
	 * @param string $algorithm Algorithm string (from JWT spec)
	 * @param string $hashType Algorithm the type resolves to
	 * @dataProvider AlgorithmDataProvider
	 */
	public function testGetSetAlgorithmResolve($algorithm, $hashType)
	{
		$header = new Header('testkey', $algorithm);
		$this->assertEquals(
			$header->getAlgorithm(true),
			$hashType
		);
	}

	/**
	 * Test that the same algorithm string is returned when no
	 * 	resolution is requested
	 */
	public function testGetSetAlgorithmNoResolve()
	{
		$algorithm = 'H256';
		$header = new Header('testkey', $algorithm);
		$this->assertEquals(
			$header->getAlgorithm(false),
			$algorithm
		);
	}

	/**
	 * Test the conversion of the header to a string of JSON
	 */
	public function testConvertToString()
	{
		$key = 'somekey';
		$algorithm = 'H256';
		$type = 'mytype';
		$header = new Header($key, $algorithm, $type);

		$this->assertEquals(
			(string)$header,
			'{"typ":"'.$type.'","alg":"'.$algorithm.'"}'
		);
	}

	/**
	 * Test the conversion of the header to an array
	 */
	public function testToArray()
	{
		$key = 'somekey';
		$algorithm = 'H256';
		$type = 'mytype';
		$header = new Header($key, $algorithm, $type);

		$this->assertEquals(
			$header->toArray(),
			array(
				'typ' => $type,
				'alg' => $algorithm
			)
		);
	}
}