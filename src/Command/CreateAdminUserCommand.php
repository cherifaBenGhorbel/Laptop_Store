<?php
// src/Command/CreateAdminUserCommand.php

namespace App\Command;  

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Console\Input\InputArgument;

class CreateAdminUserCommand extends Command
{
    protected static $defaultName = 'app:create-admin';

    private $entityManager;
    private $passwordHasher;

    public function __construct(EntityManagerInterface $entityManager, UserPasswordHasherInterface $passwordHasher)
    {
        parent::__construct();

        $this->entityManager = $entityManager;
        $this->passwordHasher = $passwordHasher;
    }

    protected function configure(): void
    {
        $this
            ->setDescription('Creates an admin user')
            ->addArgument('username', InputArgument::REQUIRED, 'The username of the admin')
            ->addArgument('password', InputArgument::REQUIRED, 'The password of the admin');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $username = $input->getArgument('username');
        $password = $input->getArgument('password');

        // Check if an admin already exists
        $existingAdmin = $this->entityManager->getRepository(User::class)->findOneBy(['isAdmin' => true]);
        if ($existingAdmin) {
            $io->error('An admin user already exists.');
            return Command::FAILURE;
        }

        $user = new User();
        $user->setUsername($username);
        $user->setRoles(['ROLE_ADMIN']);
        $user->setIsAdmin(true);
        $user->setPassword(
            $this->passwordHasher->hashPassword(
                $user,
                $password
            )
        );

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $io->success('Admin user created successfully!');

        return Command::SUCCESS;
    }
}
