<?php

namespace Psecio\Jwt\Claim;

/**
 * Claim type Not Before (nbf)
 *
 * @package Jwt
 */
class NotBefore extends \Psecio\Jwt\Claim
{
	protected $type = 'nbf';
	protected $name = 'notBefore';

	/**
	 * Validate the Issued At data
	 *
	 * @param string $value Claim data
	 * @return boolean Pass/fail of validation
	 */
	public function validate($value)
	{
		if (!is_numeric($value)) {
			return false;
		}
		return true;
	}
}