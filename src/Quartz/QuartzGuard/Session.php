<?php

namespace Ongoo\Pear\PearGuard;

use Symfony\Component\HttpFoundation\Session\Session AS SfSession;

/**
 * Description of Session
 *
 * @author paul
 */
class Session extends SfSession
{

    protected $pear_guard_user = null;
    protected $pear_guard_user_classname = null;
    protected $pear = null;

    /**
     * __construct
     *
     * @see \Symfony\Component\HttpFoundation\Session\Session
     *
     * @param \Pear\Pear $pear The Pear instance.
     * @param \Symfony\Component\HttpFoundation\Session\Storage\SessionStorageInterface $storage
     * @param \Symfony\Component\HttpFoundation\Session\Storage\AttributeBagInterface   $attributes
     * @param \Symfony\Component\HttpFoundation\Session\Storage\FlashBagInterface       $flashes
     * */
    public function __construct(\Pear\Pear $pear, $pear_guard_user_classname, \Symfony\Component\HttpFoundation\Session\Storage\SessionStorageInterface $storage = null, \Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface $attributes = null, \Symfony\Component\HttpFoundation\Session\Flash\FlashBagInterface $flashes = null)
    {
        parent::__construct($storage, $attributes, $flashes);
        $this->pear = $pear;
        $this->pear_guard_user_classname = $pear_guard_user_classname;
    }

    /**
     * setGuardUser
     *
     * Tie a user to the current session.
     * 
     * @param \Models\PearSecure\SecureUser $user
     * */
    public function setGuardUser(\Models\PearSecure\SecureUser $user)
    {
        $this->pear_guard_user = $user;
        $values = array();
        foreach ($user->getTable()->getPrimaryKeys() as $k)
        {
            $values[$k] = $user->get($k);
        }
        $this->set('pearguard_user', $values);
    }

    /**
     * removeGuardUser
     *
     * Anonymize the session.
     * */
    public function removeGuardUser()
    {
        $this->remove('pearguard_user');
    }

    /**
     * getGuardUser
     *
     * Return the current session's user if any, null otherwise.
     *
     * @return \Models\PearSecure\SecureUser
     * */
    public function getGuardUser()
    {
        if (!$this->has('pearguard_user'))
        {
            return null;
        }

        if (is_null($this->pear_guard_user))
        {
            $res = $this->pear->getTable($this->pear_guard_user_classname)->find($this->get('pearguard_user'), null, 1);
            $this->pear_guard_user = array_shift($res);
        }

        return $this->pear_guard_user;
    }

    /**
     * authenticate
     *
     * Mark the session as authenticated or not.
     *
     * @param boolean $authenticate
     * */
    public function authenticate($authenticate)
    {
        if ($authenticate === true)
        {
            $this->set('pearguard_is_authenticated', true);
        } elseif ($this->has('pearguard_is_authenticated'))
        {
            $this->remove('pearguard_is_authenticated');
        }
    }

    /**
     * isAuthenticated
     *
     * Return the authentication state.
     *
     * @return boolean
     * */
    public function isAuthenticated()
    {
        \Ongoo\Logger\Logging::get()->trace($this->all());
        return $this->has('pearguard_is_authenticated') && ($this->getGuardUser() != null);
    }

}

?>
