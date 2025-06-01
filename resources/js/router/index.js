import { createRouter, createWebHistory } from 'vue-router';

import { useAuthStore } from '../stores/auth';

import LandingPage from '../Pages/LandingPage.vue';

import LoginPage from '../Pages/Auth/LoginPage.vue';

import RegisterPage from '../Pages/Auth/RegisterPage.vue';

import ForgotPasswordPage from '../Pages/Auth/ForgotPasswordPage.vue';

// import DashboardPage from '../Pages/Auth/AuthLayout.vue';

import AuthLayout from '../Pages/Auth/AuthLayout.vue';

import DashboardHome from '../Pages/Business/DashboardHome.vue';

import ServicesPage from '../Pages/Business/ServicesPage.vue';

import UserSettings from '../Pages/Auth/UserSettings.vue';

import AppointmentsPage from '../Pages/Business/AppointmentsPage.vue';

import ScheduleServiceWizard from '../Pages/Client/ScheduleServiceWizard.vue';

const routes = [
    {
        path: '/',
        name: 'home',
        component: LandingPage,
        meta: { guest: true },
    },
    {
        path: '/login',
        name: 'login',
        component: LoginPage,
        meta: { guest: true },
    },
    {
        path: '/register',
        name: 'register',
        component: RegisterPage,
        meta: { guest: true }
    },
    {
        path: '/forgot-password',
        name: 'forgot-password',
        component: ForgotPasswordPage,
        meta: { guest: true }
    },
    {
        path: '/logout',
        name: 'logout',
        beforeEnter: async (to, from, next) => {
            const authStore = useAuthStore();
            try {
                await authStore.logout();
                
                next({ name: 'login' });
            } catch (error) {
                authStore.user = null;

                authStore.isAuthenticated = false;

                next({ name: 'login' });
            }
        }
    },
    {
        path: '/',
        component: AuthLayout,
        meta: { requiresAuth: true },
        children: [
            {
                path: 'dashboard',
                name: 'dashboard',
                component: DashboardHome,
            },
            {
                path: 'dashboard/services', // La URL completa será /dashboard/services
                name: 'dashboard-services',
                component: ServicesPage,
            },
            {
                path: 'dashboard/appointments', // La URL completa será /dashboard/appointments
                name: 'dashboard-appointments',
                component: AppointmentsPage,
            },
            {
                path: 'settings', // ¡Aquí está tu ruta de configuración de nivel superior! La URL será /settings
                name: 'UserSettings',
                component: UserSettings,
            },
        ]
    },
    {
        path: '/schedule-service',
        name: 'schedule-service',
        component: ScheduleServiceWizard,
        meta: { guest: true },
    },
    // {
    //     path: '/:pathMatch(.*)*', // Ruta catch-all para 404 (debe ser la última)
    //     name: 'NotFound',
    //     component: { template: '<div><h1>404 Page Not Found</h1></div>' } // O un componente 404
    // }
];

const router = createRouter({
    history: createWebHistory(), // Usa el modo HTML5 History (URLs limpias sin #)
    routes, // Tus rutas definidas arriba
});

router.beforeEach(async (to, from, next) => {
    const authStore = useAuthStore();

    const authPageNames = ['login', 'register', 'forgot-password'];

    const isAuthPage = authPageNames.includes(to.name);
    // 1. Siempre verificar la autenticación del backend si el store no tiene estado
    // Esto es crucial para la persistencia de la sesión al recargar la página
    if (!authStore.isAuthenticated && authStore.user === null && !isAuthPage) {
        await authStore.checkAuth();
    }

    // 2. Lógica de protección de rutas
    if (to.meta.requiresAuth && !authStore.isAuthenticated) {
        console.log('Redirigiendo a login: La ruta requiere autenticación y el usuario no está logueado.');
        next({ name: 'login' });
    } else if (to.meta.guest && authStore.isAuthenticated) {
        console.log('Redirigiendo a dashboard: La ruta es para invitados y el usuario ya está logueado.');
        next({ name: 'dashboard' });
    } else {
        next();
    }
});

// router.beforeEach(async (to, from, next) => {
//   const authStore = useAuthStore(); // Obtén la instancia del store

//   const isAuthPage = to.name === 'login' || to.name === 'register' || to.name === 'forgot-password';

//   // Asegúrate de que el estado de autenticación se verifique al cargar la app
//   // (Esto es importante para cuando el usuario refresca la página)
//     // if (!authStore.isAuthenticated && authStore.user === null) {
//     if (!authStore.isAuthenticated && authStore.user === null && !isAuthPage) {
//       // Si no estamos autenticados y no hay datos de usuario,
//       // intentamos verificar la sesión con el backend.
//       // Esto confiará en la cookie de sesión de Laravel Sanctum.
//       await authStore.checkAuth();
//     }

//   // Comprueba si la ruta requiere autenticación y el usuario no está autenticado
//   if (to.meta.requiresAuth && !authStore.isAuthenticated) {
//     console.log('Redirigiendo a login: La ruta requiere autenticación y el usuario no está logueado.');
//     next({ name: 'login' }); // Redirige a la página de login
//   }
//   // Comprueba si la ruta es para invitados y el usuario ya está autenticado
//   else if (to.meta.guest && authStore.isAuthenticated) {
//     console.log('Redirigiendo a dashboard: La ruta es para invitados y el usuario ya está logueado.');
//     next({ name: 'dashboard' }); // Redirige al dashboard
//   }
//   // Si no hay restricciones o se cumplen, permite la navegación
//   else {
//     next();
//   }
// });

// Opcional: Guardianes de navegación (ej. para redireccionar si no está autenticado)
// router.beforeEach((to, from, next) => {
//     const isAuthenticated = false; // Aquí iría tu lógica de autenticación (ej. desde un Store)

//     if (to.meta.requiresAuth && !isAuthenticated) {
//         next({ name: 'login' }); // Redirige al login si requiere auth y no está logueado
//     } else if (to.meta.guest && isAuthenticated) {
//         next({ name: 'dashboard' }); // Redirige al dashboard si es una ruta de invitado y ya está logueado
//     } else {
//         next(); // Continúa la navegación
//     }
// });

export default router; // Exporta el router para usarlo en app.js