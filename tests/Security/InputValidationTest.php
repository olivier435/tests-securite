<?php

namespace App\Tests\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DomCrawler\Crawler;
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
    public function testRegistrationAcceptsValidData()
    {
        $client = static::createClient();

        $origin = 'https://127.0.0.1:8000';
        $url = $origin . '/register';
        //1 charger le veritable formulaire
        $crawler = $client->request('GET', $url);
        //arrive sur la bonne page
        self::assertResponseIsSuccessful();

        $token = $crawler
            ->filter('input[name="registration_form[_token]"]')
            ->attr('value');
        // un eamil disponible pour cette exécution
        $email = 'registration-valid-'
            . bin2hex(random_bytes(8))
            . '@test.fr';

        //2 envoyer uniquement les champs prévus par le formulaire
        $client->request(
            'POST',
            $url,
            [
                'registration_form' => [
                    'email' => $email,
                    'plainPassword' => 'Password123!',
                    'firstname' => 'Mallory',
                    '_token' => $token,
                ],
            ],
            server: [
                'http_ORIGIN' => $origin,
                'HTTP_REFERER' => $url,
            ]
        );
        //3 etapes le parcours normal doit reussir 
        self::assertResponseRedirects('/login');
        // 4 Relire le compte depuis la base
        //cherche l'utilisateur par son eamil
        //nettoyer tes tests
        static::getContainer()
            ->get(EntityManagerInterface::class)
            ->clear();

        $user = static::getContainer()
            ->get(UserRepository::class)
            ->findOneBy(['email' => $email]);

        self::assertNotNull($user);
        self::assertSame('Mallory', $user->getFirstname());
        //5le compte cree possede des droits  ordinaires
        self::assertContains('ROLE_USER', $user->getRoles());
        self::assertNotContains('ROLE_ADMIN', $user->getRoles());
    }
    //champ cache
    public function testRegistrationCannotElevateRolesWithForgetField(): void
    {
        $client = static::createClient();

        $origin = 'https://127.0.0.1:8000';
        $url = $origin . '/register';

        // 1. Charger le formulaire et récupérer son jeton.
        $crawler = $client->request('GET', $url);

        //successfull
        self::assertResponseIsSuccessful();

        $token = $crawler
            ->filter('input[name="registration_form[_token]"]')
            ->attr('value');
        // un eamil disponible pour cette exécution
        $email = 'registration-forged-'
            . bin2hex(random_bytes(8))
            . '@test.fr';

        //envoye des données valides, avec un champ interdit en plus 
        $crawler = $client->request(
            'POST',
            $url,
            [
                'registration_form' => [
                    'email' => $email,
                    'plainPassword' => 'Password123!',
                    'firstname' => 'Mallory',
                    'roles' => ['ROLE_ADMIN'],
                    '_token' => $token,
                ],
            ],
            server: [
                'HTTP_ORIGIN' => $origin,
                'HTTP_REFERER' => $url,
            ]
        );

        // 3 la demande doit etre refusée
        self::assertResponseStatusCodeSame(422);

        // 4 recuperer les messages d'erreur afficherdans le formulaire
        $errors = $crawler
            ->filter('form[name="registration_form"] ul > li')
            ->each(
                static fn(Crawler $node): string => $node->text()
            );

        // Utiliser la traduction active du message standard de Symfony
        $expectedError = static::getContainer()
            ->get('translator')
            ->trans(
                'This form should not contain extra fields.',
                [],
                'validators'
            );

        // Une seule erreur est attentue : le champ supplémentaire.
        //Une erreur CSRF supplémentaire ferait échouer cette assertion.
        self::assertSame(
            [$expectedError],
            $errors,
            'Le refus doit être expliqué uniquement par le champ supplémentaire.'
        );
        
        //5 Vérifier l'absence réelle du compte en base
        static::getContainer()
            ->get(EntityManagerInterface::class)
            ->clear();

        $user = static::getContainer()
            ->get(UserRepository::class)
            ->findOneBy(['email' => $email]);

        self::assertNull(
            $user,
            'Aucun compte ne doit être créé à partir de cette demande refusée.'
        );
    }
}
