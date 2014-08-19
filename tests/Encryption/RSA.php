<?php

namespace SpomkyLabs\JOSE\Tests\Encryption;

use SpomkyLabs\JOSE\Encryption\RSA as Base;

class RSA extends Base
{
    private $values = array();

    public function getValue($key)
    {
        return isset($this->values[$key]) ? $this->values[$key] : null;
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

    public function setValue($key, $value)
    {
        $this->values[$key] = $value;

        return $this;
    }
}
