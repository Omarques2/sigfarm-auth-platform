import { createRouter, createWebHistory } from "vue-router";
import AccountView from "../views/AccountView.vue";
import AccountEditView from "../views/AccountEditView.vue";
import LoginView from "../views/LoginView.vue";
import ResetPasswordView from "../views/ResetPasswordView.vue";
import VerifyEmailView from "../views/VerifyEmailView.vue";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/",
      redirect: "/login",
    },
    {
      path: "/login",
      name: "login",
      component: LoginView,
    },
    {
      path: "/verify-email",
      name: "verify-email",
      component: VerifyEmailView,
    },
    {
      path: "/reset-password",
      name: "reset-password",
      component: ResetPasswordView,
    },
    {
      path: "/auth/callback",
      name: "auth-callback",
      component: LoginView,
    },
    {
      path: "/my-account",
      alias: ["/minha-conta"],
      name: "my-account",
      component: AccountView,
    },
    {
      path: "/my-account/edit",
      alias: ["/minha-conta/editar"],
      name: "my-account-edit",
      component: AccountEditView,
    },
  ],
});
