<?php

namespace Quartz\QuartzGuard;

use Silex\Application;

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
        parent::register($app);

        $app['guard.must_be_authenticated'] = $app->protect(function(\Symfony\Component\HttpFoundation\Request $request) use (&$app)
                {
                    if (!$app['session']->isAuthenticated())
                    {
                        return $app->redirect(url_for('login'));
                    }
                });

        if (!$app->offsetExists('quartzguard.config.user'))
        {
            $app['quartzguard.config.user'] = '\Models\GuardSecure\SecureUser';
        }

        $app['session'] = $app->share(function () use (&$app)
                {
                    return new \Quartz\QuartzGuard\Session($app['orm'], $app['quartzguard.config.user'], $app['session.storage.native']);
                });
    }

}

?>
