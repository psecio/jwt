<?php

namespace Psecio\Jwt\HashMethod;

class HS256 extends \Psecio\Jwt\HashMethod
{
	protected $keyType = 'HMAC';

	public function getAlgorithm()
	{
		return 'SHA256';
	}
}