<?php

namespace Psecio\Jwt\Claim;

class IssuedAt extends \Psecio\Jwt\Claim
{
	protected $type = 'iat';

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