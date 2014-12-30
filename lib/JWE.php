<?php

namespace SpomkyLabs\JOSE;

use Jose\JWE as Base;
use Jose\JWEInterface;

class JWE extends JWS implements JWEInterface
{
    use Base;
}
