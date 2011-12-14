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
//    private $logger;

    public function __construct(
                                    UserProviderInterface $userProvider,
                                    EntityManager $em
//                                    ,$logger
                                )
    {
        $this->userProvider = $userProvider;
        $this->em = $em;
//        $this->logger = $logger;
    }

    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if ($user)
        {
            if ( $this->validateDigest((string)$token->digest, $token->getUsername(), $token->nonce, $token->created, $user->getAuthSecret()) )
            {
                $authenticatedToken = new WsseUserToken(array('IS_AUTHENTICATED'));
                $authenticatedToken->setUser($user->getAuthToken());
                $authenticatedToken->setAuthenticated(TRUE);

                return $authenticatedToken;
            }
        }
        throw new AuthenticationException('The WSSE authentication failed.');
    }

    public function validateDigest($digest, $username, $nonce, $created, $secret)
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $then = new \Datetime($created, new \DateTimeZone('UTC'));
        $diff = $now->diff($then, true);

        $seconds =
            ($diff->y * 365 * 24 * 60 * 60) +
            ($diff->m * 30 * 24 * 60 * 60) +
            ($diff->d * 24 * 60 * 60) +
            ($diff->h * 60 *60) +
            ($diff->i * 60) +
            ($diff->s)
        ;

        if ($seconds > 300) {
            throw new \Exception('Expired timestamp.  Seconds: '. $seconds);
        }

        // doit: Validate nonce is unique within 5 minutes
        $rep = $this->em->getRepository('MjhWsseBundle:Nonce');

        if (!$rep->verifyAndPersistNonce($nonce, $username, 300)) {
            throw new NonceExpiredException('Previously used nonce detected');
        }

        // Validate Secret
        $expected = base64_encode(sha1($nonce . $created . $secret, true));

        return  $expected === $digest;
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof WsseUserToken;
    }
}
