<?php
require __DIR__ . '/../vendor/autoload.php';

use SLT\GoogleAuthenticator\Factory;
use SLT\GoogleAuthenticator\TOTP;

// Run Demo
$demoController = new SimpleGoogleAuthenticatorDemo();
$demoController->routeRequest();

class SimpleGoogleAuthenticatorDemo
{
    public function routeRequest()
    {
        $isAjaxRequest = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest';

        if ($isAjaxRequest) {
            $this->actionRouteJsonRequest();
        } else {
            $this->actionShowInterface();
        }
    }

    protected function actionRouteJsonRequest()
    {
        try {
            $method = isset($_POST['method']) ? $_POST['method'] : null;
            switch ($method) {
                case 'validate':
                    $this->actionValidateOTP();
                    break;

                case 'generate':
                    $this->actionGenerateOTP();
                    break;

                default:
                    throw new InvalidArgumentException('method not defined in request object');
            }
        } catch (Exception $ex) {
            $this->renderJson(
                array(
                    'success'   => false,
                    'exception' => array(
                        'class'   => get_class($ex),
                        'message' => $ex->getMessage()
                    )
                )
            );
        }
    }

    protected function actionValidateOTP()
    {
        $otp = isset($_POST['otp']) ? $_POST['otp'] : null;
        $uri = isset($_POST['uri']) ? $_POST['uri'] : null;

        /** @var $auth TOTP */
        $auth = Factory::fromUri($uri);

        $isValid = $auth->validate($otp);

        $this->renderJson(
            array(
                'success' => true,
                'data'    => array(
                    'valid' => $isValid
                )
            )
        );
    }

    protected function actionGenerateOTP()
    {
        $uri = isset($_POST['uri']) ? $_POST['uri'] : null;

        $auth = Factory::fromUri($uri);
        $this->renderJson(
            array(
                'success' => true,
                'data'    => array(
                    'otp' => $auth->calculate()
                )
            )
        );
    }

    protected function actionShowInterface()
    {
        $randomTotp = Factory::newTimeBasedAuthenticator($this->generateReadableName('@example.com'));

        $this->renderView(
            __DIR__ . '/view.phtml',
            array(
                'totp' => $randomTotp
            )
        );
    }

    protected function generateReadableName($suffix)
    {
        $string = '';
        $c = 'bcdfghjklmnprstvwz'; //consonants except hard to speak ones
        $v = 'aeiou'; //vowels
        $a = $c . $v; //both

        $numberOfSyllables = rand(2, 3);

        for ($i = 0; $i < $numberOfSyllables; $i++) {
            $string .= $c[rand(0, strlen($c) - 1)];
            $string .= $v[rand(0, strlen($v) - 1)];
            $string .= $a[rand(0, strlen($a) - 1)];
        }

        return $string . $suffix;
    }

    protected function renderJson($object)
    {
        header('Content-Type: application/json');
        echo json_encode($object);
        exit;
    }

    protected function renderView($viewPath, array $variables)
    {
        extract($variables);
        require $viewPath;
        exit;
    }
}
