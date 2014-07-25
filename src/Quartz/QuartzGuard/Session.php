<?php

namespace Quartz\QuartzGuard;

/**
 * Description of Session
 *
 * @author paul
 */
class Session extends \Ongoo\Session\Session
{

    protected $quartz_guard_user = null;
    protected $quartz_guard_user_classname = null;
    protected $orm = null;

    /**
     * __construct
     *
     * @see \Symfony\Component\HttpFoundation\Session\Session
     *
     * @param \Orm\Orm $orm The Orm instance.
     * @param \Symfony\Component\HttpFoundation\Session\Storage\SessionStorageInterface $storage
     * @param \Symfony\Component\HttpFoundation\Session\Storage\AttributeBagInterface   $attributes
     * @param \Symfony\Component\HttpFoundation\Session\Storage\FlashBagInterface       $flashes
     * */
    public function __construct(\Quartz\Quartz $orm, $quartz_guard_user_classname, \Symfony\Component\HttpFoundation\Session\Storage\SessionStorageInterface $storage = null, \Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface $attributes = null, \Symfony\Component\HttpFoundation\Session\Flash\FlashBagInterface $flashes = null)
    {
        parent::__construct($storage, $attributes, $flashes);
        $this->orm = $orm;
        $this->quartz_guard_user_classname = $quartz_guard_user_classname;
    }

    /**
     * setGuardUser
     *
     * Tie a user to the current session.
     *
     * @param \Apps\Secure\Models\SecureUser $user
     * */
    public function setGuardUser(\Apps\Secure\Models\SecureUser $user)
    {
        $this->quartz_guard_user = $user;
        $values = array();
        foreach ($user->getTable()->getPrimaryKeys() as $k)
        {
            $values[$k] = $user->get($k);
        }
        $this->set('quartzguard_user', $values);
    }

    /**
     * removeGuardUser
     *
     * Anonymize the session.
     * */
    public function removeGuardUser()
    {
        $this->remove('quartzguard_user');
    }

    /**
     * getGuardUser
     *
     * Return the current session's user if any, null otherwise.
     *
     * @return \Apps\Secure\Models\SecureUser
     * */
    public function getGuardUser()
    {
        if (!$this->has('quartzguard_user'))
        {
            return null;
        }

        if (is_null($this->quartz_guard_user))
        {
            $table = $this->orm->getTable($this->quartz_guard_user_classname);
            $values = $this->get('quartzguard_user', array());
            $criteria = array();
            foreach ($table->getPrimaryKeys() as $k)
            {
                $criteria[$k] = isset($values[$k]) ? $values[$k] : null;
            }
            
            
            $res = $table->find($criteria, null, 1);
            $this->quartz_guard_user = array_shift($res);
        }

        return $this->quartz_guard_user;
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
            $this->set('quartzguard_is_authenticated', true);
        } elseif ($this->has('quartzguard_is_authenticated'))
        {
            $this->remove('quartzguard_is_authenticated');
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
        return $this->has('quartzguard_is_authenticated') && ($this->getGuardUser() != null);
    }

}

?>
