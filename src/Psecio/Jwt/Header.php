<?php

namespace Psecio\Jwt;

class Header
{
	/**
	 * Current header type
	 * @var string
	 */
	private $type = 'JWT';

	/**
	 * Header hash setting (default SHA256)
	 * @var string
	 */
	private $algorithm = 'HS256';

	/**
	 * Header key for encoding
	 * @var string
	 */
	private $key;

	/**
	 * Hash type to encoding mapping
	 * @var array
	 */
	private $hashTypes = array(
		'HS256' => 'SHA256',
		'HS384' => 'SHA384',
		'HS512' => 'SHA512',
	);

	/**
	 * Intitialize the Header
	 *
	 * @param string $key Key to use for encoding
	 * @param string $algorithm Algorithm to use [optional]
	 * @param string $type Type of object [optional]
	 */
	public function __construct($key, $algorithm = 'HS256', $type = 'JWT')
	{
		$this->setType($type);
		$this->setAlgorithm($algorithm);
		$this->setKey($key);

		// If it's a certificate, we're a JWS instead
		if (is_resource($key)) {
			$this->setType('JWS');
		}
	}

	/**
	 * Set the header type
	 *
	 * @param string $type Header type
	 * @return \Psecio\Jwt\Header instance
	 */
	public function setType($type)
	{
		$this->type = $type;
		return $this;
	}

	/**
	 * Return the current type
	 *
	 * @return string Current type setting
	 */
	public function getType()
	{
		return $this->type;
	}

	/**
	 * Set the algorithm type
	 *
	 * @param string $algorithm Algorithm type
	 * @return \Psecio\Jwt\Header instance
	 */
	public function setAlgorithm($algorithm)
	{
		$this->algorithm = $algorithm;
		return $this;
	}

	/**
	 * Get the current algorithm setting
	 *  If "resolve" is set to true, it finds the value from the types array
	 *  and returns that
	 *
	 * @param boolean $resolve Resolve the algorithm to its type
	 * @return string Algorithm setting (or resolved value)
	 */
	public function getAlgorithm($resolve = false)
	{
		$algorithm = $this->algorithm;
		if ($resolve === true) {
			foreach ($this->hashTypes as $key => $algo) {
				if ($key === $algorithm) {
					return $this->hashTypes[$key];
				}
			}
		}
		return $algorithm;
	}

	/**
	 * Set the current object's key value
	 *
	 * @param string $key Key to use for encoding
	 * @return \Psecio\Jwt\Header instance
	 */
	public function setKey($key)
	{
		$this->key = $key;
		return $this;
	}

	/**
	 * Get the currently set key
	 *
	 * @return string Current key string
	 */
	public function getKey()
	{
		return $this->key;
	}

	/**
	 * Convert the object to a JSON string
	 *
	 * @return string JSON formatted string
	 */
	public function __toString()
	{
		$data = $this->toArray();
		return json_encode($data);
	}

	/**
	 * Convert the object into an array of data
	 *
	 * @return array Object data as an array
	 */
	public function toArray()
	{
		$data = array(
			'typ' => $this->getType(),
			'alg' => $this->getAlgorithm()
		);
		return $data;
	}
}