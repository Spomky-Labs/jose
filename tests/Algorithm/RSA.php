<?php

namespace SpomkyLabs\JOSE\Tests\Algorithm;

use SpomkyLabs\JOSE\Algorithm\RSA as Base;

/**
 */
class RSA extends Base
{
    protected $values = array();

    public function __construct()
    {
        $this->setValue('kty', 'RSA');
    }
    
    public function getValue($key)
    {
        return isset($this->values[$key]) ? $this->values[$key] : null;
    }

    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }

    public function getValues()
    {
        return $this->values;
    }

    public function setValues(array $values)
    {
        $this->values = $values;

        return $this;
    }
}
