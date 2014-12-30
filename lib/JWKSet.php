<?php

namespace SpomkyLabs\JOSE;

abstract class JWKSet implements JWKSetInterface
{
    public function isEmpty()
    {
        return count($this->getKeys()) === 0;
    }

    public function __toString()
    {
        $keys = $this->getKeys();
        $result = array(
            'keys' => array(),
        );
        foreach ($keys as $key) {
            $result['keys'][] = $key->getValues();
        }

        return json_encode($result);
    }
}
