<?php

namespace App\Tests\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class InputValidationTest extends WebTestCase
{
    public function testUserEntityRejectsInvalidInput(): void
    {
        //demarre le noyeau de symfony test lire la conifiguration dans le package rend le serveur acessible static containe

        self::bootKernel();

        $user = (new User())
            ->setEmail('not-an-email')
            ->setFirstname('')
            ->setPassword('not-used-by-validation');

        $violations = static::getContainer()
            ->get(ValidatorInterface::class) // recuperation du service 
            ->validate($user); //validation de l'entite des contraints dans l'entite 
        //stock les chemins proprietes
        $invalidProperties = [];
        foreach ($violations as $violation) {
            $invalidProperties[] = $violation->getPropertyPath();
        }

        //assertion si il y'a une violation propriete email
        //webtestcase test fonctionnel
        self::assertContains('email', $invalidProperties);
        self::assertContains('firstname', $invalidProperties);
    }
    //tester les codes erreur 400 et 422 requete json bon element ne sont pas bon
    //n'est pas un bon format400
    public function testApiReturns422ForInvalidJsonPayload(): void
    {
        //validation desdonnées dans une application
        //cree navigateur
        $client = static::createClient();
        $client->jsonRequest('POST', '/api/register', [
            'email' => 'abc',
            'password' => '123',
            'firstname' => '',
        ]);
        //recu un code 422 verifier
        self::assertResponseStatusCodeSame(422);
        //deuxieme verification si c'est bien json
        self::assertResponseHeaderSame('content-type', 'application/json');

        $data = json_decode((string) $client->getResponse()->getContent(), true, flags: JSON_THROW_ON_ERROR);
        //decoder json //cherche dans le navigateur client stocke dans data
        self::assertArrayHasKey('email', $data['errors']);
        self::assertArrayHasKey('password', $data['errors']);
        self::assertArrayHasKey('firstname', $data['errors']);
    }

    public function testMalformedJsonReturns400(): void
    {
        $client = static::createClient();
        $client->request(
            'POST',
            '/api/register',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: '{"eamil":'
        );

        self::assertResponseStatusCodeSame(400);
    }
    //champ cache
    public function testRegistrationCannotElevateRolesWithForgetField(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/register');
        $token = $crawler->filter('input[name="registration_form[_token]"]')->attr('value');
        $email = sprintf('mallory-$s@test.fr', bin2hex(random_bytes(5)));
        //champ cache role user 
        $client->request(
            'POST',
            '/register',
            [
                'registration_form' => [
                    'email' => $email,
                    'plainPassword' => 'Password123!',
                    'firstname' => 'Mallory',
                    'roles' => ['ROLE_ADMIN'],
                    '_token' => $token,
                ]
            ],
            server: ['HTTP_REFERER' => 'https:127.0.0.1:8000/register']
        );
        self::assertResponseStatusCodeSame(422);

        $user = static::getContainer()->get(UserRepository::class)
            ->findOneBy(['email' => $email]);
        //pas utilisateur
        self::assertNull($user);
    }
}
