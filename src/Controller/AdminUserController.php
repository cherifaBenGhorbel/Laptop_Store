<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * @Route("/admin/user")
 * @IsGranted("ROLE_ADMIN")
 */
class AdminUserController extends AbstractController
{
    /**
     * @Route("/", name="admin_user_index", methods={"GET"})
     */
    public function index(UserRepository $userRepository): Response
    {
        $clients = $userRepository->findBy(['isAdmin' => false]);
        return $this->render('admin_user/index.html.twig', [
            'users' => $clients,
        ]);
    }

    /**
     * @Route("/new", name="admin_user_new", methods={"GET", "POST"})
     */
    public function new(Request $request, UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $entityManager, UserRepository $userRepository): Response
    {
        // Ensure there's no existing admin before creating a new one
        $existingAdmin = $userRepository->findOneBy(['isAdmin' => true]);
        if ($existingAdmin) {
            throw $this->createAccessDeniedException('There is already an admin user.');
        }

        $user = new User();
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // Ensure new user is an admin
            $user->setIsAdmin(true);
            $user->setRoles(['ROLE_ADMIN']);

            // Hash the plain password
            $user->setPassword(
                $passwordHasher->hashPassword(
                    $user,
                    $form->get('plainPassword')->getData()
                )
            );

            $entityManager->persist($user);
            $entityManager->flush();

            return $this->redirectToRoute('admin_user_index');
        }

        return $this->render('admin_user/new.html.twig', [
            'user' => $user,
            'form' => $form->createView(),
        ]);
    }

    /**
     * @Route("/{id}/edit", name="admin_user_edit", methods={"GET", "POST"})
     */
    public function edit(Request $request, User $user, UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $entityManager): Response
    {
        // Ensure admin is not editing another admin
        if ($user->getIsAdmin()) {
            throw $this->createAccessDeniedException('You cannot edit another admin.');
        }

        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // Hash the plain password
            if ($form->get('plainPassword')->getData()) {
                $user->setPassword(
                    $passwordHasher->hashPassword(
                        $user,
                        $form->get('plainPassword')->getData()
                    )
                );
            }

            $entityManager->flush();

            return $this->redirectToRoute('admin_user_index');
        }

        return $this->render('admin_user/edit.html.twig', [
            'user' => $user,
            'form' => $form->createView(),
        ]);
    }

    /**
     * @Route("/{id}", name="admin_user_delete", methods={"POST"})
     */
    public function delete(Request $request, User $user, EntityManagerInterface $entityManager): Response
    {
        // Ensure admin is not deleting another admin
        if ($user->getIsAdmin()) {
            throw $this->createAccessDeniedException('You cannot delete another admin.');
        }

        if ($this->isCsrfTokenValid('delete' . $user->getId(), $request->request->get('_token'))) {
            $entityManager->remove($user);
            $entityManager->flush();
        }

        return $this->redirectToRoute('admin_user_index');
    }
}
