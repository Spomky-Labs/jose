<?php

namespace SpomkyLabs\JOSE;

use Jose\JWS as Base;
use Jose\JWSInterface;

class JWS extends JWT implements JWSInterface
{
    use Base;
}
