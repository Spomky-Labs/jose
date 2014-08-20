<?php

namespace SpomkyLabs\JOSE;

/**
 * Interface representing a JSON Web Token Manager.
 */
interface JWTManagerInterface
{
    /**
     * Load data and try to return a string, an array, JWK or JWKSet object depending on the content type.
     *   - If the data loaded is a JWS, the result will be a JWT
     *   - If the data loaded is a JWE, the result could be:
     *       - a string
     *       - a an array
     *       - a JWK (an encrypted key that contains private material) @see JWK section 7
     *       - a JWKSet (an encrypted key set that contains private materials) @see JWK section 7
     *
     * @param  string    $data A string that represents a JSON Web Token message
     * @throws Exception
     *
     * @return string|array|JWKInterface|JWKSetInterface
     */
    public function load($data);

    /**
     * Convert a JWK/JWKSet object, a string or an array into its compact serialized Json representation.
     * The conversion will use the JWK object to sign or encrypt depending on the capabilityes of the key.
     * If the input is a string, a JWK or a JWKSet object, only encryption is available.
     *
     * @param  JWKInterface|JWKSetInterface|string|array $input  A JWK/JWKSet object, a string or an array
     * @param  JWKInterface                              $jwk    The JWK used to signed or encrypt
     * @param  array                                     $header The header. MUST at least contain 'enc' value
     * @return string
     * @throws Exception                                 If the key is not able to sign or encrypt
     */
    public function convertToCompactSerializedJson($input, JWKInterface $jwk, array $header = array());

    /**
     * Convert a JWK/JWKSet object, a string or an array into its serialized Json representation.
     * The conversion will use the JWK object to sign or encrypt depending on the capabilityes of the key.
     * If the input is a string, a JWK or a JWKSet object, only encryption is available.
     *
     * @param  JWTInterface    $jwt     The JWT object
     * @param  JWKSetInterface $jwk_set A JWKSet used to signed or encrypt
     * @return string
     * @throws Exception       If the key is not able to sign or encrypt
     */
    public function convertToSerializedJson(JWTInterface $jwt, JWKSetInterface $jwk_set);
}
