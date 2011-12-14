<?php

namespace MJH\WsseBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * MJH\WsseBundle\Entity\Nonce
 *
 * @ORM\Table()
 * @ORM\Entity(repositoryClass="MJH\WsseBundle\Entity\NonceRepository")
 */
class Nonce
{
    /**
     * @var integer $id
     *
     * @ORM\Column(name="id", type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private $id;

    /**
     * @var string $nonce
     *
     * @ORM\Column(name="nonce", type="string", length=255)
     */
    private $nonce;

    /**
     * @ORM\Column(name="auth_token", type="string", length=255)
     */
    private $auth_token;

    /**
     * @ORM\Column(name="created_at", type="datetime")
     */
    private $created_at;


    /**
     * Get id
     *
     * @return integer
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set nonce
     *
     * @param string $nonce
     */
    public function setNonce( $nonce )
    {
        $this->nonce = $nonce;
    }

    /**
     * Get nonce
     *
     * @return string
     */
    public function getNonce()
    {
        return $this->nonce;
    }


    /**
     * Set created_at
     *
     * @param datetime $createdAt
     */
    public function setCreatedAt( $createdAt )
    {
        $this->created_at = $createdAt;
    }

    /**
     * Get created_at
     *
     * @return datetime
     */
    public function getCreatedAt()
    {
        return $this->created_at;
    }

    /**
     * Set auth_token
     *
     * @param string $authToken
     */
    public function setAuthToken( $authToken )
    {
        $this->auth_token = $authToken;
    }

    /**
     * Get auth_token
     *
     * @return string
     */
    public function getAuthToken()
    {
        return $this->auth_token;
    }
}