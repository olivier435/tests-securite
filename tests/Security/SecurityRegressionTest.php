<?php

namespace App\Tests\Security;

use App\Repository\PurchaseOrderRepository;
use App\Repository\UserRepository;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

#[Group('security-regression')]
class SecurityRegressionTest extends WebTestCase
{
    //un visisteur anonym allez a l'espace admin
    /**
     * un visisteur anonyme ne doit pas pouvoir accedere a l espace administration
     *
     * @return void
     */
    public function testAdminAreaStillRequiresAuthentication(): void
    {
        $client = static::createClient();
        $crawler = $client->request('GET', '/admin');

        self::assertResponseRedirects('/login');
    }


    /**
     * un visisteur authentifie sans role admin doit toujours 
     * recevoir une reponse 403
     *
     */

    public function testStandardUserStillCannotAccessAdminArea(): void
    {
        $client = static::createClient();

        $user = static::getContainer()
            ->get(UserRepository::class)
            ->findOneBy(['email' => 'user@test.fr']);

        self::assertNotNull($user);

        $client->loginUser($user);

        $client->request('GET', '/admin');

        self::assertResponseStatusCodeSame(403);
    }
    /**
     * la protection ne doit pas bloquer les uilisateur
     * qui dispoent rellement du rol adminsitrateur
     *
     */

    public function testAdministratorCanStillAccessAdminArea(): void
    {
        $client = static::createClient();

        $admin = static::getContainer()
            ->get(UserRepository::class)
            ->findOneBy(['email' => 'admin@test.fr']);

        self::assertNotNull($admin);

        $client->loginUser($admin);

        $client->request('GET', '/admin');

        self::assertResponseIsSuccessful(200);
        self::assertAnySelectorTextContains('h1', 'Administration');
    }

    /**
     * le proprietaire d'une commande doit toujours
     * pouvoir consulter son propre ressource
     */

    public function testOrderOwnerCanStillAsccessOwnOrder(): void
    { {
            $client = static::createClient();
            //pourpouvoir allez sur la page commentaire chercher user pour etre connecte
            $user = static::getContainer()->get(UserRepository::class)
                ->findOneBy(['email' => 'user@test.fr']);
            $order = static::getContainer()->get(PurchaseOrderRepository::class)
                ->findOneBy(['reference' => 'SEC-001']);

            self::assertNotNull($user);
            self::assertNotNull($order);
            self::assertSame(
                $user->getId(),
                $order->getOwner()?->getId()
            );


            $client->loginUser($user);
            $client->request('GET', '/orders/' . $order->getId());

            self::assertResponseIsSuccessful();
            self::assertSelectorTextContains('h1', 'SEC-001');
        }
    }
    /**
     * test vote run utilisateurne doit jamais 
     * pouvoir consulter la commande d'un autre utilisateur
     */


    public function testIdorProtectionIsStillApplied(): void
    {
        //static la classe de test herite de web test case accessible grace a l heritage deux methode static
        $client = static::createClient();

        $user = static::getContainer()
            ->get(UserRepository::class)
            ->findOneBy(['email' => 'user@test.fr']);

        $foreignorder = static::getContainer()
            ->get(PurchaseOrderRepository::class)
            ->findOneBy(['reference' => 'SEC-002']);

        self::assertNotNull($user);
        self::assertNotNull($foreignorder);
        self::assertNotSame(
            $user->getId(),
            $foreignorder->getOwner()?->getId()
        );
        //404 permet d envoyer une indication au hack je ne sais pas si la ressource existe j envoie le message ne trouve pas je ne sais pas si cela existe 
        //construction 403 il passe par defaut 
        $client->loginUser($user);
        $client->request(
            'GET',
            '/orders/' . $foreignorder->getId()
        );

        self::assertResponseStatusCodeSame(403);
    }
    /**
     * une tentative de suppression sans token CSRF 
     * doit etre refusée sans suprimer le compte
     */

    public function testRejectedAccountDeletionDoesNotDeleteUSer(): void
    {
        $client = static::createClient();

        $email = 'user@test.fr';

        $user = static::getContainer()
            ->get(UserRepository::class)
            ->findOneBy(['email' => $email]);

        self::assertNotNull($user);

        $client->loginUser($user);
        $client->request('POST', '/account/delete');

        self::assertResponseStatusCodeSame(403);

        $userAfterRequest = static::getContainer()
            ->get(UserRepository::class)
            ->findOneBy(['email' => $email]);

        self::assertNotNull($userAfterRequest);
    }
}
