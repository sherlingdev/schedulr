import { defineStore } from 'pinia';
import axios from 'axios';
import router from '../router';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    isAuthenticated: false,
  }),
  actions: {
    async login(credentials) {
      try {
        // 1. Obtener la cookie CSRF de Sanctum (preflight request)
        await axios.get('/sanctum/csrf-cookie');

        // 2. Enviar credenciales al backend
        const response = await axios.post('/login', credentials);

        // 3. Actualizar el estado con la información del usuario
        this.user = response.data.user;
        this.isAuthenticated = true;

        // 4. Redirigir al dashboard
        router.push('/dashboard');

        return response.data; // Retorna la respuesta para manejo adicional si es necesario
      } catch (error) {
        console.error('Error de inicio de sesión:', error);
        this.user = null;
        this.isAuthenticated = false;
        throw error; // Re-lanza el error para que el componente pueda manejarlo (ej. mostrar mensaje)
      }
    },

    async logout() {
      try {
        await axios.post('/logout');

        this.user = null;

        this.isAuthenticated = false;
      } catch (error) {
        this.user = null;
        
        this.isAuthenticated = false;

        throw error;
      }
    },

    async checkAuth() {
      try {
        // const response = await axios.get('/api/user');
        // if (response.data && typeof response.data === 'object' && Object.keys(response.data).length > 0) {
        //     this.user = response.data;
        //     this.isAuthenticated = true;
        //     console.log("Usuario autenticado establecido:", this.user, this.isAuthenticated);
        // } else {
        //     console.warn("checkAuth: Datos de usuario no recibidos o vacíos (aunque 200 OK):", response.data);
        //     this.user = null;
        //     this.isAuthenticated = false;
        // }
        // console.log(response);
        // this.user = response.data && Object.keys(response.data).length > 0 ? response.data : null;
        // this.isAuthenticated = response.data && Object.keys(response.data).length > false;
        // console.log(this.user);
        // console.log(this.isAuthenticated);
        this.user = null;
        this.isAuthenticated = false;
      } catch (error) {
        this.user = null;
        this.isAuthenticated = false;
      }
    },
  },
});