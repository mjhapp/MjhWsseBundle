Intent: Create a WSSE provider, including a Symfony2 client and a vanilla PHP client

Right now, this is basically a direct copy of the Symfony2 Cookbook entry on creating a custom authentication provider.

This is meant to be used for protecting web services on top of Symfony2

Installation
============

1.  in deps, add
```
[MjhWsseBundle]
    git=http://github.com/mjhapp/MjhWsseBundle.git
    target=/bundles/MJH/WsseBundle
```
2.  add to AppKernel.php
```php
new MJH\WsseBundle\MjhWsseBundle(),
```
3.  add to autoload.php
```php
'MJH'                            => __DIR__.'/../vendor/bundles',
```
4.  in security.yml
```yaml
security:
    factories:
        - "%kernel.root_dir%/../vendor/bundles/MJH/WsseBundle/Resources/config/security_factories.xml"
providers:
    wsse_provider:
        entity:
            class: Acme\DemoBundle\Entity\User  # This Entity class must implement UserProvider
firewalls:
    wsse_secured:
        pattern: ^/api/.*
        wsse: true
        provider: wsse_provider
```



5.  entity class for user / consumer / etc.
```php
class UserRepository extends EntityRepository implements UserProviderInterface
{

    /**
    *
    * The following functions support UserProviderInterfare requirements for WSSE
    *
    */

    public function loadUserByUsername($username)
    {
        $user = $this->findOneBy(array('auth_token' => $username));

        return $user;
    }

    public function refreshUser(UserInterface $user)
    {
        return $this->loadUserByUsername($user->getAuthToken());
    }

    public function supportsClass($class)
    {
        return $class === 'Acme\DemoBundle\Entity\User';
    }
}
```