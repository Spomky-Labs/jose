<?php

namespace SpomkyLabs\JOSE;

use Jose\JWK as Base;

class JWK extends Base
{
    protected $values = array();

    public function jsonSerialize()
    {
        return $this->getValues();
    }

    public function getValue($key)
    {
        return array_key_exists($key, $this->getValues()) ? $this->values[$key] : null;
    }

    public function getValues()
    {
        return $this->values;
    }

    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }

    public function setValues(array $values)
    {
        $this->values = $values;

        return $this;
    }
}
