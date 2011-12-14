<?php
namespace MJH\WsseBundle\Security\Authentication\Request;

use \Exception;
use \DateTime;

class WsseRequest
{
    private $username;
    private $secret;

    private $digest;
    private $nonce;
    private $timestamp;

    private $url;
    private $post_data = NULL;

    public function __construct($url, $post_data=NULL, $username=NULL, $secret=NULL)
    {
        $this->setSecret($secret);
        $this->setUsername($username);
        $this->setUrl($url);
        $this->setPostData($post_data);
    }

    public function setUsername( $username )
    {
        $this->username = $username;
    }

    public function setSecret( $secret )
    {
        $this->secret = $secret;
    }

    public function setUrl( $url )
    {
        $this->url = $url;
    }

    public function setPostData( $post_data )
    {
        $this->post_data = $post_data;
    }

    private function setDigest()
    {
        $this->setTimestamp();
        $this->setNonce();

        if ( !$this->nonce || !$this->timestamp || !$this->secret)
        {
            throw new \Exception('Insufficient information to generate digest');
        }

        $this->digest = base64_encode(sha1($this->nonce.$this->timestamp.$this->secret, true));
    }

    public function getDigest()
    {
        return $this->digest;
    }

    private function setTimestamp()
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $this->timestamp = (string)$now->format('Y-m-d\TH:i:s\Z');
    }

    private function getTimestamp()
    {
        return $this->timestamp;
    }

    private function setNonce()
    {
        $this->nonce = substr( base64_encode(sha1(time() . 'salt')) ,0,16);
    }

    private function getNonce()
    {
        return $this->nonce;
    }

    private function getWsseHeader()
    {
        return sprintf('X-WSSE: UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"',
            $this->username,
            $this->digest,
            $this->nonce,
            $this->timestamp
        );
    }

    public function sendRequest()
    {
        $this->setDigest();

        if (!$this->username)
        {
            throw new \Exception('No user provided');
        }

        return $this->sendCurlRequest();
    }

    private function sendCurlRequest()
    {
        $headers = array(
            $this->getWsseHeader()
        );

        $post = array(
            $this->post_data
        );

        $ch = curl_init($this->url);

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if ($this->post_data)
        {
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
        }

        $result = curl_exec($ch);

        if (!$result)
        {
            $result = curl_error($ch);
        }
        curl_close($ch);

        return $result;

    }


}