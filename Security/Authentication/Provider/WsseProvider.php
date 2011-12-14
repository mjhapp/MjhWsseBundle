<?php
namespace MJH\WsseBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use MJH\WsseBundle\Security\Authentication\Token\WsseUserToken;
use Doctrine\ORM\EntityManager;
use Symfony\Component\DependencyInjection\ContainerAware;

class WsseProvider extends ContainerAware implements AuthenticationProviderInterface
{
    private $userProvider;
    private $em;

    public function __construct( UserProviderInterface $userProvider, EntityManager $em )
    {
        $this->userProvider = $userProvider;
        $this->em = $em;
    }

    public function authenticate( TokenInterface $token )
    {
        $user = $this->userProvider->loadUserByUsername( $token->getUsername() );

        if ( $user )
        {
            if ( $this->validateDigest(
                (string)$token->digest,
                $token->getUsername(),
                $token->nonce,
                $token->created,
                $user->getAuthSecret() )
            )
            {
                $authenticatedToken = new WsseUserToken(array('IS_AUTHENTICATED'));
                $authenticatedToken->setUser( $user->getAuthToken() );
                $authenticatedToken->setAuthenticated( TRUE );

                return $authenticatedToken;
            }
        }
        throw new AuthenticationException('The WSSE authentication failed.');
    }

    public function validateDigest( $digest, $username, $nonce, $created, $secret )
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $then = new \Datetime($created, new \DateTimeZone('UTC'));
        $diff = $now->diff( $then, true );

        $seconds =
            ($diff->y * 365 * 24 * 60 * 60) +
                ($diff->m * 30 * 24 * 60 * 60) +
                ($diff->d * 24 * 60 * 60) +
                ($diff->h * 60 * 60) +
                ($diff->i * 60) +
                ($diff->s);

        // Validate timestamp is recent within 5 minutes
        if ( $seconds > 300 )
        {
            throw new \Exception('Expired timestamp.  Seconds: ' . $seconds);
        }

        // Validate nonce is unique within 5 minutes
        $rep = $this->em->getRepository( 'MjhWsseBundle:Nonce' );

        if ( !$rep->verifyAndPersistNonce( $nonce, $username, 300 ) )
        {
            throw new NonceExpiredException('Previously used nonce detected');
        }

        // Validate Secret
        $expected = base64_encode( sha1( $nonce . $created . $secret, true ) );

        // Return TRUE if our newly-calculated digest is the same as the one provided in the validateDigest() call
        return $expected === $digest;
    }

    public function supports( TokenInterface $token )
    {
        return $token instanceof WsseUserToken;
    }
}
