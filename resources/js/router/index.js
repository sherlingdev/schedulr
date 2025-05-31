// resources/js/router/index.js

import { createRouter, createWebHistory } from 'vue-router';

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
        path: '/', // La ruta padre será la raíz, pero el componente es el layout
        component: AuthLayout, // Este componente tiene el sidebar y el <router-view>
        meta: { requiresAuth: true },
        children: [
            {
                path: 'dashboard', // La ruta para el home del dashboard será /dashboard
                name: 'dashboard', // Nombre de la ruta principal del dashboard
                component: DashboardHome, // El contenido de la página de inicio del dashboard
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
            // Puedes agregar otras rutas que necesiten el layout aquí, por ejemplo:
            // {
            //     path: 'profile',
            //     name: 'UserProfile',
            //     component: UserProfilePage,
            // },
            // {
            //     path: 'help-info', // Nueva ruta para Ayuda e Información
            //     name: 'HelpInfo',
            //     component: { template: '<div class="space-y-6"><h1 class="text-3xl font-bold text-gray-900">Ayuda e Información</h1><p class="text-gray-700">Contenido de ayuda aquí.</p></div>' }
            // }
        ]
    },
    // {
    //     path: '/dashboard',
    //     name: 'dashboard',
    //     component: DashboardPage,
    //     meta: { requiresAuth: true },
    //     children: [
    //         {
    //             path: 'services',
    //             name: 'dashboard-services',
    //             component: ServicesPage,
    //         },
    //         {
    //             path: 'appointments',
    //             name: 'dashboard-appointments',
    //             component: AppointmentsPage,
    //         },
    // //         {
    // //     path: 'settings',
    // //     name: 'UserSettings',
    // //     component: UserSettings
    // //   },
    //     ]
    // },
    {
        path: '/schedule-service',
        name: 'schedule-service',
        component: ScheduleServiceWizard,
        meta: { guest: true },
    },
    // {
    //     path: '/settings',
    //     name: 'UserSettings',
    //     component: UserSettings,
    //     meta: { requiresAuth: true }
    // },
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

// router.beforeEach((to, from, next) => {
//     const isAuthenticated = true; // **IMPORTANTE: Aquí debe ir tu lógica de autenticación real**

//     if (to.meta.requiresAuth && !isAuthenticated) {
//         next({ name: 'login' });
//     } else if (to.meta.guest && isAuthenticated) {
//         next({ name: 'dashboard' });
//     } else {
//         next();
//     }
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