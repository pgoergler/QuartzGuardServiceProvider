<?php

namespace Quartz\QuartzGuard;

use Silex\Application,
    Symfony\Component\HttpFoundation\Session\Storage\Handler\NativeFileSessionHandler,
    Symfony\Component\HttpFoundation\Session\Storage\NativeSessionStorage,
    Symfony\Component\HttpFoundation\Request,
    Symfony\Component\HttpFoundation\Response
;

/**
 * Description of QuartzServiceProvider
 *
 * @author paul
 */
class QuartzGuardServiceProvider extends \Silex\Provider\SessionServiceProvider
{

    public function boot(Application $app)
    {
        $app['orm']->init($app['quartz.databases']); // to init database
    }

    public function register(Application $app)
    {
        $this->app = $app;


        if (!isset($app['quartzguard.config.user']) )
        {
            $app['quartzguard.config.user'] = '\Apps\Secure\Models\SecureUser';
        }

        if( !isset($app['session.storage.save_path']) )
        {
            $app['session.storage.save_path'] = './';
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
                
        $app['guard.credentialized'] = $app->protect(function() use (&$app){
            $credentials = func_get_args();
            return function(\Symfony\Component\HttpFoundation\Request $request) use (&$app, $credentials) {
                if( !$app->offsetExists('session') )
                {
                    $app->abort(401, 'Must be authenticated');
                }
                
                if( !$app['session']->isStarted() )
                {
                    $app['session']->start();
                }
                
                if (!$app['session']->isAuthenticated())
                {
                    $app->abort(401, 'Must be authenticated');
                }
                
                $user = $app['session']->getGuardUser();
                if( !$user )
                {
                    $app->abort(401, 'Must be authenticated');
                }
                
                if( !$user->hasCredentials($credentials) )
                {
                    $app->abort(401, 'Unauthorized');
                }
            };
        });
        
        $app['guard.redirect_on'] = $app->protect(function($code, $url) use (&$app){
            $args = func_get_args();
            $code = array_shift($args);
            $url = array_shift($args);
            
            return function(Request $request, Response $response) use (&$app, $code, $url, $args) {
                if( $response->getStatusCode() == $code ) {
                    if( is_callable($url) )
                    {
                        $app['logger']->debug('callable');
                        return $url($request, $response);
                    }
                    return $app->redirect(url_for($url, $args));
                }
            };
        });
    }

}

?>
