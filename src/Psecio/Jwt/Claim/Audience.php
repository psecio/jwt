<?php

namespace Psecio\Jwt\Claim;

/**
 * Claim type Audience (aud)
 *
 * @package Jwt
 */
class Audience extends \Psecio\Jwt\Claim
{
	protected $type = 'aud';
    protected $name = 'audience';
}