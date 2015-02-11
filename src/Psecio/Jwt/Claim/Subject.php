<?php

namespace Psecio\Jwt\Claim;

/**
 * Claim type Subject (sub)
 *
 * @package Jwt
 */
class Subject extends \Psecio\Jwt\Claim
{
	protected $type = 'sub';
    protected $name = 'subject';
}