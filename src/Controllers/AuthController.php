<?php

namespace Engelsystem\Controllers;

use Carbon\Carbon;
use Engelsystem\Database\Db;
use Engelsystem\Helpers\Authenticator;
use Engelsystem\Http\Request;
use Engelsystem\Http\Response;
use Engelsystem\Http\UrlGeneratorInterface;
use Engelsystem\Models\User\Contact;
use Engelsystem\Models\User\PersonalData;
use Engelsystem\Models\User\Settings;
use Engelsystem\Models\User\State;
use Engelsystem\Models\User\User;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class AuthController extends BaseController
{
    /** @var Response */
    protected $response;

    /** @var SessionInterface */
    protected $session;

    /** @var UrlGeneratorInterface */
    protected $url;

    /** @var Authenticator */
    protected $auth;

    /** @var array */
    protected $permissions = [
        'login'     => 'login',
        'postLogin' => 'login',
    ];

    /**
     * @param Response              $response
     * @param SessionInterface      $session
     * @param UrlGeneratorInterface $url
     * @param Authenticator         $auth
     */
    public function __construct(
        Response $response,
        SessionInterface $session,
        UrlGeneratorInterface $url,
        Authenticator $auth
    ) {
        $this->response = $response;
        $this->session = $session;
        $this->url = $url;
        $this->auth = $auth;
    }

    /**
     * @return Response
     */
    public function login(): Response
    {
        return $this->showLogin();
    }

    /**
     * @return Response
     */
    protected function showLogin(): Response
    {
        $errors = Collection::make(Arr::flatten($this->session->get('errors', [])));
        $this->session->remove('errors');

        return $this->response->withView(
            'pages/login',
            ['errors' => $errors]
        );
    }

    /**
     * Posted login form
     *
     * @param Request $request
     * @return Response
     */
    public function postLogin(Request $request): Response
    {
        $data = $this->validate($request, [
            'login'    => 'required',
            'password' => 'required',
        ]);

        $user = $this->auth->authenticate($data['login'], $data['password']);

        if (!$user instanceof User) {
            $this->session->set('errors', $this->session->get('errors', []) + ['auth.not-found']);

            return $this->showLogin();
        }

        $this->session->invalidate();
        $this->session->set('user_id', $user->id);
        $this->session->set('locale', $user->settings->language);

        $user->last_login_at = new Carbon();
        $user->save(['touch' => false]);

        return $this->response->redirectTo('news');
    }

    /**
     * @return Response
     */
    public function logout(): Response
    {
        $this->session->invalidate();

        return $this->response->redirectTo($this->url->to('/'));
    }

    public function startoidc() : Response
    {
        $url = config('oidc_url');
        $id = config('oidc_client_id');
        $secret = config('oidc_client_secret');
        $oidc = new OpenIDConnectClient($url, $id, $secret);
        $oidc->addScope(array('openid', 'email'));
        $oidc->providerConfigParam(['token_endpoint_auth_methods_supported' => []]);
        try {
            $oidc->authenticate();
        } catch (OpenIDConnectClientException $e) {
            return $this->response->redirectTo($this->url->to('/login'));
        }

        $user = $this->auth->userRepository->whereName($oidc->getVerifiedClaims('sub'))->first();
        if ($user instanceof User) {
            $this->session->invalidate();
            $this->session->set('user_id', $user->id);
            $this->session->set('locale', $user->settings->language);

            $user->last_login_at = new Carbon();
            $user->save(['touch' => false]);

            return $this->response->redirectTo('news');
        }
        else {

            $nick = $oidc->getVerifiedClaims('sub');
            $mail = $oidc->getIdTokenPayload()->email;

//            $selected_angel_types = [];
//            foreach (array_keys($angel_types) as $angel_type_id) {
//                if ($request->has('angel_types_' . $angel_type_id)) {
//                    $selected_angel_types[] = $angel_type_id;
//                }
//            }

                $user = new User([
                    'name'          => $nick,
                    'password'      => '',
                    'email'         => $mail,
                    'api_key'       => '',
                    'last_login_at' => null,
                ]);
                $user->save();

                $contact = new Contact([
                    'dect'   => '',
                    'mobile' => '',
                ]);
                $contact->user()
                    ->associate($user)
                    ->save();

                $personalData = new PersonalData([
                    'first_name'           => '',
                    'last_name'            => '',
                    'shirt_size'           => '',
                    'planned_arrival_date' => null,
                ]);
                $personalData->user()
                    ->associate($user)
                    ->save();

                $settings = new Settings([
                    'language'        => 'de_DE',
                    'theme'           => config('theme'),
                    'email_human'     => true,
                    'email_shiftinfo' => true,
                ]);
                $settings->user()
                    ->associate($user)
                    ->save();

                $state = new State([]);
                if (config('autoarrive')) {
                    $state->arrived = true;
                    $state->arrival_date = new Carbon();
                }
                $state->user()
                    ->associate($user)
                    ->save();

                // Assign user-group and set password
                DB::insert('INSERT INTO `UserGroups` (`uid`, `group_id`) VALUES (?, -20)', [$user->id]);

//                // Assign angel-types
//                $user_angel_types_info = [];
//                foreach ($selected_angel_types as $selected_angel_type_id) {
//                    DB::insert(
//                        'INSERT INTO `UserAngelTypes` (`user_id`, `angeltype_id`, `supporter`) VALUES (?, ?, FALSE)',
//                        [$user->id, $selected_angel_type_id]
//                    );
//                    $user_angel_types_info[] = $angel_types[$selected_angel_type_id];
//                }

                engelsystem_log(
                    'User ' . User_Nick_render($user, true)
                    . ' signed up'
                );
                success(__('Angel registration successful!'));


                // If a welcome message is present, display registration success page.
                if ($message = config()->get('welcome_msg')) {
                    return User_registration_success_view($message);
                }


        }

        return $this->response->redirectTo($this->url->to('/'));
    }
}
