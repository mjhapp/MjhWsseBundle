<?php
namespace MJH\WsseBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use MJH\WsseBundle\Security\Authentication\Token\WsseUserToken;
use Doctrine\ORM\EntityManager;

class WsseProvider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $em;

    public function __construct(UserProviderInterface $userProvider, EntityManager $em)
    {
        $this->userProvider = $userProvider;
        $this->em = $em;
    }

    public function authenticate(TokenInterface $token)
    {        
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if ( $user && $this->validateDigest($token->digest, $token->getUsername(), $token->nonce, $token->created, $user->getAuthSecret())) {
            $authenticatedToken = new WsseUserToken(array('IS_AUTHENTICATED'));
            $authenticatedToken->setUser($user->getAuthToken());

            return $authenticatedToken;
        }
        
        throw new AuthenticationException('The WSSE authentication failed.');
    }

    protected function validateDigest($digest, $username, $nonce, $created, $secret)
    {
//        return true;
        // Expire timestamp after 5 minutes
        // Times must be represented in UTC format
//        if (time() - strtotime($created) > 300) {
          if (time() - time() > 300 ){
            return false;
        }
        
//        return true;

        // Validate nonce is unique within 5 minutes
        $rep = $this->em->getRepository('MjhWsseBundle:Nonce');
        
        if ( !$rep->verifyAndPersistNonce($nonce, $username, 300))
        {
          throw new NonceExpiredException('Previously used nonce detected');
        }

        return true;

        // Validate Secret
        $expected = base64_encode(sha1($nonce.$created.$secret, true));

        return $digest === $expected;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof WsseUserToken;
    }
}
