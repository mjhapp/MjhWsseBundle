Intent: Create a WSSE provider, including a Symfony2 client and a vanilla PHP client

Right now, this is basically a direct copy of the Symfony2 Cookbook entry on creating a custom authentication provider.

This is meant to be used for protecting web services on top of Symfony2

#To-do

 * _**DONE!**_ - Annoying: Can't get final compare of signatures to work... Strings are identical and '===' is returning true, but
    exception is thrown when the function returns.   Returning true manually works fine.  Calculating an SHA1 on each
    one is also identical.  This needs to be solved asap. ... ... ... As it turned out, I had forgotten to set the token
    as authenticated... As a result, the listener was getting called a second time (why?) to validate the new token,
    which was now sans a timestamp and digest value.
 * _**DONE!**_ - Format timestamp as UTC
 * _**DONE!**_ - Handle timezones appropriately when generating / parsing times
 * Provide a mechanism to purge expired nonces
 * _**DONE!**_ - Handle curl errors better
 * Build full headers for the curl request
 * Provide support for non-curl-enabled installations
 * Provide extras folder with additional clients
    * _**DONE!**_ - Non-namespaced PHP  -- I just stripped the namespace and use off and saved in another file.
    * Ruby
    * Javascript
    * Java
    * These are probably available already, but should be included
  * Clean up commented debug stuff - logging, etc.
  * _**DONE!**_Create getResponse(), hasError(), getError() in the client class

#Installation

##Update Dependencies

```
[MjhWsseBundle]
    git=http://github.com/mjhapp/MjhWsseBundle.git
    target=/bundles/MJH/WsseBundle
```
##Update AppKernel.php

``` php
new MJH\WsseBundle\MjhWsseBundle(),
```
##Update autoload.php

``` php
'MJH'                            => __DIR__.'/../vendor/bundles',
```
##Update security.yml - add factory, add user provider, add firewall

``` jinja
security:
    factories:
        - "%kernel.root_dir%/../vendor/bundles/MJH/WsseBundle/Resources/config/security_factories.xml"
providers:
    wsse_provider:
        entity:
            class: Acme\DemoBundle\Entity\User  # This class must implement UserProviderIterface
firewalls:
    wsse_secured:
        pattern: ^/api/.*
        wsse: true
        provider: wsse_provider
```



##Implement UserProviderInterface on the class that will be providing user accounts to the security system

``` php
<?php
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

#Client Usage

```php
<?php
// SecuredController.php


namespace Acme\DemoBundle\Controller;

...
use MJH\WsseBundle\Security\Authentication\Request\WsseRequest;
...


class SecuredController extends Controller
{

    public function indexAction(Request $request)
    {
        ...
        $wsseRequest = new WsseRequest('http://theapp.nut/api/v1/getsome.php', null, 'mjhapp','secret');

        $wsseResult = $wsseRequest->sendRequest();  // right now, 'sendRequest()' retuns the result of the curl call
                                                    // this will change in the next push when error and result methods
                                                    // are added

        return array(
           ...
         );
    }
}
```