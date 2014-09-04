<?php

namespace SpomkyLabs\JOSE;

/**
 * Interface representing a JSON Web Token Manager.
 */
interface JWTManagerInterface
{
    /**
     * Load data and try to return a string, an array, a JWK or a JWKSet object depending on the content type.
     *   - If the data loaded is a JWS, the result could be a string or an array
     *   - If the data loaded is a JWE, the result could be:
     *       - a string
     *       - a an array
     *       - a JWK (an encrypted key that contains private material) @see JWK section 7
     *       - a JWKSet (an encrypted key set that contains private materials) @see JWK section 7
     *
     * @param  string    $input  A string that represents a JSON Web Token message
     * @param  array     $header An optionnal array that will contain the headers used to decrypt or verify the signature.
     * @throws Exception If a signature has not been verified or if decryption failed
     *
     * @return string|array|JWKInterface|JWKSetInterface If the JWT have been loaded, this result will contain the payload depending on the content type.
     */
    public function load($input,array &$header = array());

    /**
     * Sign a string or an array and convert it into its JSON (Compact) Serialized representation.
     *
     * @param boolean         $compact        If true, the result will be a JSON Compact Serialized JWT. The argument $operation_keys must contain only one private key
     * @param string|array    $input          A JWK/JWKSet object, a string or an array
     * @param JWKSetInterface $operation_keys An array that contain, for each signature, an index 'key' (JWKInterface object) used to signed the input, an index 'protected' (array) with the protected header (MUST contain at least index 'alg') and index 'header' (optionnal) to add unprotected header for the signature.
     *
     * @return string    The JSON (Compact) Serialized representation
     * @throws Exception
     */
    public function signAndConvert($compact, $input, array $operation_keys);

    /**
     * Encrypt a string, an array, a JWK or a JWKSet object and convert it into its JSON (Compact) Serialized representation.
     *
     * @param boolean         $compact            If true, the result will be a JSON Compact Serialized JWT. The argument $recipients must contain only one recipient key
     * @param string|array    $input              A JWK/JWKSet object, a string or an array
     * @param JWKSetInterface $operation_keys     An array that contain, for each recipient, an index 'key' (JWKInterface object) used to encrypt the CEK, an index 'header' (optionnal array) with the unprotected header.
     * @param array           $protected_header   The protected header.
     * @param array           $unprotected_header The unprotected header (optionnal).
     * @param JWKInterface    $sender_key         If the input if encrypted, some algorithm may require the key of the sender (e.g.: ECDH-ES, PBES-*).
     *
     * @return string    The JSON (Compact) Serialized representation
     * @throws Exception
     */
    public function encryptAndConvert($compact, $input, array $operation_keys, array $protected_header = null, array $unprotected_header = null, JWKInterface $sender_key = null);
}
