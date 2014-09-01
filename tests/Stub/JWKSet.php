<?php

namespace SpomkyLabs\JOSE\Tests;

use SpomkyLabs\JOSE\JWKSet as Base;

class JWKSet extends Base
{
    private $keys = array();

    public function getKeys()
    {
        return $this->keys;
    }

    /**
     * Set keys in the Key
     * @param JWKInterface $key A JWKInterface objects
     */
    public function addKey(JWKInterface $key)
    {
        $this->keys[] = $key;

        return $this;
    }
}
