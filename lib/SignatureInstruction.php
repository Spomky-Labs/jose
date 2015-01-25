<?php

namespace SpomkyLabs\Jose;

use Jose\JWKInterface;
use Jose\SignatureInstructionInterface;

class SignatureInstruction implements SignatureInstructionInterface
{
    protected $key = null;
    protected $protected_header = array();
    protected $unprotected_header = array();

    public function setKey(JWKInterface $key)
    {
        $this->key = $key;

        return $this;
    }

    public function getKey()
    {
        return $this->key;
    }

    public function setProtectedHeader(array $protected_header)
    {
        $this->protected_header = $protected_header;

        return $this;
    }

    public function getProtectedHeader()
    {
        return $this->protected_header;
    }

    public function setUnprotectedHeader(array $unprotected_header)
    {
        $this->unprotected_header = $unprotected_header;

        return $this;
    }

    public function getUnprotectedHeader()
    {
        return $this->unprotected_header;
    }
}
