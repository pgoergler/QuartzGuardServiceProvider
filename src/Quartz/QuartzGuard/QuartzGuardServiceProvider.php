<?php

namespace Quartz\QuartzGuard;

use Silex\Application;
use Symfony\Component\HttpFoundation\Session\Storage\Handler\NativeFileSessionHandler;
use Symfony\Component\HttpFoundation\Session\Storage\NativeSessionStorage;

/**
 * Description of QuartzServiceProvider
 *
 * @author paul
 */
class QuartzGuardServiceProvider extends \Silex\Provider\SessionServiceProvider
{

    public function boot(Application $app)
    {
        $app['quartz']->init($app['quartz.databases']); // to init database
    }

    public function register(Application $app)
    {
        $this->app = $app;
        
        
        if (!isset($app['quartzguard.config.user']) )
        {
            $app['quartzguard.config.user'] = '\Models\GuardSecure\SecureUser';
        }
        
        if( !isset($app['session.storage.save_path']) )
        {
            $app['session.storage.save_path'] = __W_ROOT_DIR . '/sessions';
        }

        $app['session.test'] = false;

        $app['session'] = $app->share(function ($app) {
            if (!isset($app['session.storage'])) {
                if ($app['session.test']) {
                    $app['session.storage'] = $app['session.storage.test'];
                } else {
                    $app['session.storage'] = $app['session.storage.native'];
                }
            }

            return new \Quartz\QuartzGuard\Session($app['orm'], $app['quartzguard.config.user'], $app['session.storage']);
        });

        $app['session.storage.handler'] = $app->share(function ($app) {
            return new NativeFileSessionHandler($app['session.storage.save_path']);
        });

        $app['session.storage.native'] = $app->share(function ($app) {
            return new NativeSessionStorage(
                $app['session.storage.options'],
                $app['session.storage.handler']
            );
        });

        $app['session.storage.test'] = $app->share(function() {
            return new MockFileSessionStorage();
        });

        $app['guard.must_be_authenticated'] = $app->protect(function(\Symfony\Component\HttpFoundation\Request $request) use (&$app)
                {
                    if( !$app['session']->isStarted() )
                    {
                        $app['session']->start();
                    }
                    
                    if (!$app['session']->isAuthenticated())
                    {
                        return $app->redirect(url_for('login'));
                    }
                });
    }

}

?>
