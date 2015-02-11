<?php

namespace Psecio\Jwt\Claim;

/**
 * Claim type Custom
 *
 * @package Jwt
 */
class Custom extends \Psecio\Jwt\Claim
{
	protected $type;
    protected $name = 'custom';

    /**
     * Initialize the claim with the given value and type
     *
     * @param string $value Claim value
     * @param string $type Type value
     */
    public function __construct($value, $type)
    {
        $this->setValue($value);
        $this->setType($type);
    }

    /**
     * Set the claim type
     *
     * @param string $type Claim type
     * @return \Psecio\Jwt\Claim instance
     */
    public function setType($type)
    {
        $this->type = $type;
        return $this;
    }
}