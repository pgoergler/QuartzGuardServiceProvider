<?php

namespace Quartz\QuartzGuard;

/**
 * Description of Session
 *
 * @author paul
 */
class Session extends \Ongoo\Session\Session
{

    protected $quartz_guard_prefix = 'auth';
    protected $quartz_guard_user = null;
    protected $quartz_guard_user_classname = null;
    protected $orm = null;
    
    private $salt = "AZRGESGZERT3A04TKQZE0Q23IR0QZI34RQ30I423940C303K0RK20230R";

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
    public function __construct(\Quartz\Quartz $orm, $quartz_guard_user_classname, \Symfony\Component\HttpFoundation\Session\Storage\SessionStorageInterface $storage = null, \Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface $attributes = null, \Symfony\Component\HttpFoundation\Session\Flash\FlashBagInterface $flashes = null, $prefix = 'auth')
    {
        parent::__construct($storage, $attributes, $flashes);
        $this->orm = $orm;
        $this->quartz_guard_user_classname = $quartz_guard_user_classname;
        $this->quartz_guard_prefix = $prefix;
    }

    public function getTokenName()
    {
        return sprintf("quartzguard_token_%s", $this->quartz_guard_prefix );
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
        $this->set($this->getTokenName(), $user->getExtraVar('token', null));
    }

    /**
     * removeGuardUser
     *
     * Anonymize the session.
     * */
    public function removeGuardUser()
    {
        $this->remove($this->getTokenName());
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
        if (!$this->has($this->getTokenName()))
        {
            return null;
        }
        
        if (is_null($this->quartz_guard_user))
        {
            $table = $this->orm->getTable($this->quartz_guard_user_classname);
            $token = $this->get($this->getTokenName(), '?');
            
            $criteria = array(
                sprintf("extra_infos->'token' = '%s'", $table->escape($token, 'string'))
            );
            $res = $table->find($criteria, null, 1);
            $this->quartz_guard_user = $res->current();
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
    public function isAuthenticated(\Symfony\Component\HttpFoundation\Request $request)
    {
        if( is_null($this->getGuardUser()) )
        {
            return false;
        }
        
        if( !$this->has('quartzguard_is_authenticated'))
        {
            return false;
        }
        
        if( !$this->get('quartzguard_is_authenticated', false))
        {
            return false;
        }
        
        return $this->buildBrowserToken($request) === $this->getGuardUser()->getExtraVar('token_ua', '');
    }
    
    public function buildBrowserToken(\Symfony\Component\HttpFoundation\Request $request)
    {
        $salt = $this->salt . $this->salt;
        $token = '';
        $token .= $salt . $request->getClientIp() . $salt;
        $token .= $salt . implode(",", $request->getCharsets()) . $salt;
        $token .= $salt . $request->headers->get('user-agent'). $salt;
        $token .= $salt . $request->headers->get('accept-language'). $salt;
        
        return sha1($token);
    }
    
    public function buildToken(\Apps\Secure\Models\SecureUser $user)
    {
        $salt = $this->salt;
        $token = '';
        foreach ($user->getTable()->getPrimaryKeys() as $k)
        {
            $token .= $salt . $k . "=" . $user->get($k) . $salt;
        }
        
        return sha1($token);
    }

}

?>
