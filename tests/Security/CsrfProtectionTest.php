<?php

namespace App\Tests\Security;

use App\Repository\UserRepository;
use App\Tests\Support\CreatesUsers;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class CsrfProtectionTest extends WebTestCase
{
    use CreatesUsers;

    //cas1 token valide
    public function testAccountFormContainsCsrfToken(): void
    {
        $client = static::createClient();
        $user = static::getContainer()->get(UserRepository::class)
            ->findOneBy(['email' => 'user@test.fr']);
        //user qui existe pas
        self::assertNotNull($user);
        //se connection
        $client->loginUser($user);
        //acces a la modification
        $client->request('GET', '/account/edit');

        //si existe selector token
        self::assertResponseIsSuccessful();
        self::assertSelectorExists('input[name="account[_token]"]');
    }
    //cas numero2 token falsifier

    public function testAutomaticFormRejectsInvalidCsrfToken(): void
    {
        $client = static::createClient();
        $user = static::getContainer()->get(UserRepository::class)
            ->findOneBy(['email' => 'user@test.fr']);

        self::assertNotNull($user);

        $client->loginUser($user);

        $crawler = $client->request('GET', '/account/edit');
        $form = $crawler->selectButton('Enregistrer')->form([
            'account[email]' => 'user@test.fr',
            'account[firstname]' => 'Bob',
            'account[_token]' => 'hack'
        ]);

        $client->submit($form);

        self::assertResponseStatusCodeSame(422);
        self::assertAnySelectorTextContains('body', 'CSRF');
    }
    //cas numero 3 token absent code 403

    public function testManualActionRejectsMissingCsrfToken(): void
    {
        $client = static::createClient();
        $user = static::getContainer()->get(UserRepository::class)
            ->findOneBy(['email' => 'user@test.fr']);

        self::assertNotNull($user);

        $client->loginUser($user);
        $client->request('POST', '/account/delete');

        self::assertResponseStatusCodeSame(403);
    }

    //cas numero 4 token autre action supprimer un utilisateur 

    public function testManualActionRejectsForgedCsrfToken(): void
    {
        $client = static::createClient();
        $user = static::getContainer()->get(UserRepository::class)
            ->findOneBy(['email' => 'user@test.fr']);

        self::assertNotNull($user);

        $client->loginUser($user);
        $client->request('POST', '/account/delete',  ['_token' => 'hack']);

        self::assertResponseStatusCodeSame(403);
    }
    //cas 5 positif suppresion d'un utilisateur (positif)

    public function testManualActionAcceptsValidCsrfToken(): void
    {
        $client = static::createClient();
        $email = sprintf(
            'delete-%s@test.fr',
            bin2hex(random_bytes(5))
            //utiliser des identifiants differents test verifie base dedonnée et suppriem
        );
        //cree utilisateur appel trait
        $user = $this->createTestUser($email);
        //connecte loginuser 
        $client->loginUser($user);

        $crawler = $client->request('GET', '/account');

        $token = $crawler
            ->filter(
                'form[action="/account/delete"] input[name="_token"]'
            )
            ->attr('value');

        $client->request('POST', '/account/delete',  ['_token' => $token]);

        self::assertResponseRedirects('/');

        //plus en session
        /**
         * Verifie que la redirection ne provoque plus l'erreur 
         * liée à l'utilisateur supprime conservé dans le token
         */
        $client->followRedirect();

        self::assertResponseIsSuccessful();
        self::assertSelectorTextContains('h1', 'Bienvenue');

        //le compte doit avoir ete supprimer dans la base de donéne$
        $deletedUser = static::getContainer()->get(UserRepository::class)
            ->findOneBy(['email' => $email]);

        self::assertNull($deletedUser);
        //l'ancien utilisateur doit egalement etre connecte
        $client->request('GET', '/account');

        self::assertResponseRedirects('/login');
    }
}
