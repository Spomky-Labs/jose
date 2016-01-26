<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2015 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

interface JWSInterface extends JWTInterface
{
    /**
     * @return null|string
     */
    public function getEncodedPayload();

    /**
     * Returns the number of signature associated with the JWS.
     *
     * @return int
     */
    public function countSignatures();

    /**
     * @param \Jose\Object\SignatureInterface $signature
     *
     * @return \Jose\Object\JWSInterface
     */
    public function addSignature(SignatureInterface $signature);

    /**
     * Returns the signature associated with the JWS.
     *
     * @return \Jose\Object\SignatureInterface[]
     */
    public function getSignatures();

    /**
     * @param int $id
     *
     * @return \Jose\Object\SignatureInterface
     */
    public function getSignature($id);

    /**
     * @param int $id
     *
     * @return string
     */
    public function toCompactJSON($id);

    /**
     * @param int $id
     *
     * @return string
     */
    public function toFlattenedJSON($id);

    /**
     * @return string
     */
    public function toJSON();
}
