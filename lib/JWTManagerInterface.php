<?php

namespace SpomkyLabs\JOSE;

use SpomkyLabs\JOSE\JWTInterface;
use SpomkyLabs\JOSE\JWKInterface;
use SpomkyLabs\JOSE\JWKSetInterface;

/**
 * Interface representing a JSON Web Token Manager.
 */
interface JWTManagerInterface
{
    /**
     * Creates an empty JWTInterface object
     * 
     * @return JWTInterface
     */
    public function createJWT();

    /**
     * Load data and try to return a JWT object
     * 
     * @param string $data A string that represents a JSON Web Token message
     * @throws Exception
     * 
     * @return JWTInterface
     */
    public function load($data);

    /**
     * Convert a JWT object into its compact serialized Json representation.
     * The conversion will use the JWK object to sign or encrypt.
     * This function must try to encrypt first, if the key can not encrypt, it will try to sign.
     * 
     * @param  JWTInterface $jwt The JWT object
     * @param  JWKInterface $jwk The JWK used to signed or encrypt
     * @return string
     * @throws Exception If the key is not able to sign or encrypt
     */
    public static function convertToCompactSerializedJson(JWTInterface $jwt, JWKInterface $jwk);

    /**
     * Convert a JWT object into its serialized Json representation.
     * The conversion will use the JWK objects to sign or encrypt.
     * This function must try to encrypt first, if the key can not encrypt, it will try to sign.
     * 
     * @param  JWTInterface    $jwt     The JWT object
     * @param  JWKSetInterface $jwk_set A JWKSet used to signed or encrypt
     * @return string
     * @throws Exception If the key is not able to sign or encrypt
     */
    public static function convertToSerializedJson(JWTInterface $jwt, JWKSetInterface $jwk_set);
}
