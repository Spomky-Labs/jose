<?php

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2016 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

namespace Jose\Object;

/**
 * Class EncryptionInstruction.
 */
final class EncryptionInstruction implements EncryptionInstructionInterface
{
    /**
     * @var array
     */
    protected $recipient_unprotected_header = [];
    /**
     * @var \Jose\Object\JWKInterface
     */
    protected $recipient_public_key;
    /**
     * @var null|\Jose\Object\JWKInterface
     */
    protected $sender_private_key = null;

    /**
     * EncryptionInstruction constructor.
     *
     * @param \Jose\Object\JWKInterface      $recipient_public_key
     * @param \Jose\Object\JWKInterface|null $sender_private_key
     * @param array                          $recipient_unprotected_header
     */
    public function __construct(JWKInterface $recipient_public_key, JWKInterface $sender_private_key = null, array $recipient_unprotected_header = [])
    {
        $this->sender_private_key = $sender_private_key;
        $this->recipient_public_key = $recipient_public_key;
        $this->recipient_unprotected_header = $recipient_unprotected_header;
    }

    /**
     * {@inheritdoc}
     */
    public function getRecipientKey()
    {
        return $this->recipient_public_key;
    }

    /**
     * {@inheritdoc}
     */
    public function getSenderKey()
    {
        return $this->sender_private_key;
    }

    /**
     * {@inheritdoc}
     */
    public function getRecipientUnprotectedHeader()
    {
        return $this->recipient_unprotected_header;
    }
}
