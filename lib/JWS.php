<?php

namespace SpomkyLabs\Jose;

use Jose\JWS as Base;

/**
 * Class JWS
 * @package SpomkyLabs\Jose
 */
class JWS extends Base
{
    use JWable;

    protected $input;
    protected $signature;

    public function getInput()
    {
        return $this->input;
    }

    public function setInput($input)
    {
        $this->input = $input;

        return $this;
    }

    public function getSignature()
    {
        return $this->signature;
    }

    public function setSignature($signature)
    {
        $this->signature = $signature;

        return $this;
    }
}
