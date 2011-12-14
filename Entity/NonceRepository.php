<?php

namespace MJH\WsseBundle\Entity;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query;
use MJH\WsseBundle\Entity\Nonce;
use \DateTime;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * NonceRepository
 *
 * This class was generated by the Doctrine ORM. Add your own custom
 * repository methods below.
 */
class NonceRepository extends EntityRepository
{
    public function verifyAndPersistNonce( $nonce, $username, $duration = 300 )
    {
        if ( !$nonce )
        {
            throw new AuthenticationException('No nonce provided');
        }

        $noncetime = new DateTime('@' . (time() - $duration), new \DateTimeZone('UTC'));

        $nonces = $this->getEntityManager()
            ->createQuery( 'SELECT n FROM
              MjhWsseBundle:Nonce n
              WHERE n.nonce = :nonce
                AND n.auth_token = :username
                AND n.created_at > :noncetime' )
            ->setParameter( 'nonce', $nonce )
            ->setParameter( 'username', $username )
            ->setParameter( 'noncetime', $noncetime->format( 'Y-m-d\TH:i:s\Z' ) )
            ->getResult();

        if ( count( $nonces ) == 0 )
        {
            $newNonce = new Nonce();
            $newNonce->setNonce( $nonce );
            $newNonce->setCreatedAt( new DateTime() );
            $newNonce->setAuthToken( $username );
            $em = $this->getEntityManager();

            $em->persist( $newNonce );
            $em->flush();

            return true;
        }

        return false;
    }
}