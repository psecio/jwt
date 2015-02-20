<?php

namespace Psecio\Jwt\HashMethod;

class HS512 extends \Psecio\Jwt\HashMethod
{
	protected $keyType = 'HMAC';

	public function getAlgorithm()
	{
		return 'SHA512';
	}
}