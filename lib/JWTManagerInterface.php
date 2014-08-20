<?php

namespace SpomkyLabs\JOSE;

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
     * Load data and try to return a JWT, JWK or JWKSet object depending on the content.
     *   - If the data loaded is a JWS, the result will be a JWT
     *   - If the data loaded is a JWE, the result could be:
     *       - a JWT
     *       - a JWK (an encrypted key that contains private material) @see JWK section 7
     *       - a JWKSet (an encrypted key set that contains private materials) @see JWK section 7
     *
     * @param  string    $data A string that represents a JSON Web Token message
     * @throws Exception
     *
     * @return JWTInterface|JWKInterface|JWKSetInterface
     */
    public function load($data);

    /**
     * Convert a JWT/JWK/JWKSet object or a string into its compact serialized Json representation.
     * The conversion will use the JWK object to sign or encrypt depending on the capabilityes of the key.
     * If the input is a string, a JWK or a JWKSet object, only encryption is available.
     *
     * @param  JWTInterface|JWKInterface|JWKSetInterface|string $input A JWT/JWK/JWKSet object or a string
     * @param  JWKInterface                                     $jwk   The JWK used to signed or encrypt
     * @return string
     * @throws Exception                                        If the key is not able to sign or encrypt
     */
    public function convertToCompactSerializedJson($input, JWKInterface $jwk, array $header = array());

    /**
     * Convert a JWT object into its serialized Json representation.
     * The conversion will use the JWK objects to sign or encrypt.
     * This function must try to encrypt first, if the key can not encrypt, it will try to sign.
     *
     * @param  JWTInterface    $jwt     The JWT object
     * @param  JWKSetInterface $jwk_set A JWKSet used to signed or encrypt
     * @return string
     * @throws Exception       If the key is not able to sign or encrypt
     */
    public function convertToSerializedJson(JWTInterface $jwt, JWKSetInterface $jwk_set);
}
