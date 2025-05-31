<template>
  <div class="flex h-screen bg-gray-50">
    <div class="w-64 bg-white shadow-sm flex flex-col">
      <div class="flex items-center justify-center h-16 border-b border-gray-100">
        <span class="font-bold text-gray-800 text-2xl">Schedulr</span>
      </div>

      <nav class="flex-1 px-2 py-4 space-y-2">
        <router-link to="/dashboard"
                     class="flex items-center px-3 py-2 text-gray-700 hover:bg-gray-100 hover:text-gray-900 rounded-md font-medium text-sm"
                     active-class="bg-gray-200 text-gray-900"
                     exact-active-class="bg-gray-200 text-gray-900" exact> <svg class="h-5 w-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m0 0l-7 7m7-7v10a1 1 0 01-1 1h-3m-6-6a1 1 0 001 1h1a1 1 0 001-1v-1a1 1 0 00-1-1h-1a1 1 0 00-1 1v1z"></path></svg>
          Home
        </router-link>

        <router-link to="/dashboard/services"
                     class="flex items-center px-3 py-2 text-gray-700 hover:bg-gray-100 hover:text-gray-900 rounded-md font-medium text-sm"
                     active-class="bg-gray-200 text-gray-900">
          <svg class="h-5 w-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 13.255A23.582 23.082 0 0110.25 10.5m0 0c-3.111-3.111-7.854-3.111-10.965 0L1 21M3 21h18"></path></svg>
          Servicios
        </router-link>

        <router-link to="/dashboard/appointments"
                     class="flex items-center px-3 py-2 text-gray-700 hover:bg-gray-100 hover:text-gray-900 rounded-md font-medium text-sm"
                     active-class="bg-gray-200 text-gray-900">
          <svg class="h-5 w-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>
          Citas
        </router-link>

        <!-- <router-link to="/dashboard/tasks"
                     class="flex items-center px-3 py-2 text-gray-700 hover:bg-gray-100 hover:text-gray-900 rounded-md font-medium text-sm"
                     active-class="bg-gray-200 text-gray-900">
          <svg class="h-5 w-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"></path></svg>
          Tareas
        </router-link>
        
        <router-link to="/dashboard/team"
                     class="flex items-center px-3 py-2 text-gray-700 hover:bg-gray-100 hover:text-gray-900 rounded-md font-medium text-sm"
                     active-class="bg-gray-200 text-gray-900">
          <svg class="h-5 w-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20v-2a4 4 0 00-4-4H9a4 4 0 00-4 4v2m3-2a4 4 0 004 4h4a4 4 0 004-4m-1-5a2 2 0 11-4 0 2 2 0 014 0zM12 11a4 4 0 100-8 4 4 0 000 8z"></path></svg>
          Equipo
        </router-link>

        <router-link to="/dashboard/settings"
                     class="flex items-center px-3 py-2 text-gray-700 hover:bg-gray-100 hover:text-gray-900 rounded-md font-medium text-sm"
                     active-class="bg-gray-200 text-gray-900">
          <svg class="h-5 w-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.827 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.827 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.827-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.827-3.31 2.37-2.37a1.724 1.724 0 002.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
          Configuración
        </router-link> -->
      </nav>

      <div class="px-2 py-4 mt-auto">
        <div class="bg-gray-100 p-4 rounded-md text-sm text-gray-700">
          <p class="font-semibold mb-2">Upgrade a Pro</p>
          <p class="text-xs mb-3">Obtén 1 mes gratis y desbloquea todas las funciones.</p>
          <button class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
            Upgrade
          </button>
        </div>
      </div>

      <div class="px-2 py-4 space-y-2 border-t border-gray-100">
         <router-link to="/settings"
                     class="flex items-center px-3 py-2 text-gray-700 hover:bg-gray-100 hover:text-gray-900 rounded-md font-medium text-sm"
                     active-class="bg-gray-200 text-gray-900">
          <svg class="h-5 w-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9.247a8.672 8.672 0 001.391.802c.491.246.969.465 1.42.666m-.426-.604c-.394.394-.852.748-1.391.802-.491.246-.969.465-1.42.666a.75.75 0 00-.001 1.05l.001.001a.75.75 0 001.05-.001m.001-.001a.75.75 0 00-.001-1.05zM12 12c-1.657 0-3 1.343-3 3s1.343 3 3 3 3-1.343 3-3-1.343-3-3-3z"></path></svg>
          Ayuda e Información
        </router-link>
        <router-link to="/logout"
                     class="flex items-center px-3 py-2 text-gray-700 hover:bg-gray-100 hover:text-gray-900 rounded-md font-medium text-sm"
                     active-class="bg-gray-200 text-gray-900">
          <svg class="h-5 w-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
          Cerrar Sesión
        </router-link>
      </div>
    </div>

    <div class="flex-1 p-6 overflow-auto">
      <router-view></router-view> </div>
  </div>
</template>

<script>
import { ref } from 'vue';

export default {
  name: 'DashboardPage',
  setup() {
    return {};
  },
};
</script>

<style scoped>
/* No se necesitan estilos específicos aquí, Tailwind CSS lo maneja */
</style>