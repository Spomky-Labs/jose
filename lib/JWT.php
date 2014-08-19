<?php

namespace SpomkyLabs\JOSE;

use SpomkyLabs\JOSE\Base64Url;

/**
 * Class representing a JSON Web Token.
 */
abstract class JWT implements JWTInterface
{
    /**
     * {@inheritdoc}
     */
    public function isExpired()
    {
        $nbf = $this->getValue('nbf');
        $exp = $this->getValue('exp');
        $now = (new \DateTime('now'))->format('U');

        if ($nbf !== null && $now < $exp)
        {
            return true;
        }
        if ($exp !== null && $now > $exp)
        {
            return true;
        }
        return false;
    }
}
