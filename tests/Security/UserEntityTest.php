<?php

namespace App\Tests\Security;

use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class UserEntityTest extends KernelTestCase
{
    public function testUserEntityRejectsInvalidInput(): void
    {
        //test service symfony test Kermel
        //test integration tester service
        self::bootKernel();

        $user = (new User())
            ->setEmail('not-an-email')
            ->setFirstname('')
            ->setPassword('not-used-by-validation');

        $validator = static::getContainer()
            ->get(ValidatorInterface::class);

        $violations = $validator->validate($user);

        $invalidProperties = [];
        foreach ($violations as $violation) {
            $invalidProperties[] = $violation->getPropertyPath();
        }

        self::assertContains('email', $invalidProperties);
        self::assertContains('firstname', $invalidProperties);
    }
}
