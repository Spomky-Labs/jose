<?php

namespace SpomkyLabs\JOSE;

use SpomkyLabs\JOSE\JWKSetInterface;

abstract class JWKSet implements JWKSetInterface
{
    public function toPublic()
    {
        $result = array();
        foreach ($this->getKeys() as $key) {
            $result[] = $key->toPublic();
        }
        return $result;
    }

    public function toPrivate()
    {
        $result = array();
        foreach ($this->getKeys() as $key) {
            $result[] = $key->toPrivate();
        }
        return $result;
    }
}
