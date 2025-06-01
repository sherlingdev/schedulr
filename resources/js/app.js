import './bootstrap';

import axios from 'axios';

window.axios = axios;

window.axios.defaults.withCredentials = true;

window.axios.defaults.baseURL = 'http://127.0.0.1:8000';

axios.interceptors.response.use(
  response => response,
  error => {
    if (error.response && error.response.status === 401) {
      // Aquí puedes redirigir al usuario al login
      // O disparar una acción/mutación en tu store de autenticación para limpiar el estado
      // Ej: store.dispatch('auth/logout'); // Si usas Vuex
      // Ej: authStore.logout(); // Si usas Pinia
      // router.push('/login'); // Requiere que 'router' esté disponible globalmente o inyectado
    }
    return Promise.reject(error);
  }
);

import { createApp } from 'vue';

import App from './App.vue';

import router from './router';

import { createPinia } from 'pinia';

const app = createApp(App);

const pinia = createPinia();

app.use(pinia);

app.use(router);

app.mount('#app');