<template>
  <div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-xl">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        Configuración Personal
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        Gestiona la información de tu cuenta, como tu correo electrónico, contraseña y otros detalles personales.
      </p>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-3xl"> <div class="bg-white py-8 px-4 shadow-sm sm:rounded-lg sm:px-10">

        <div class="border-b border-gray-200">
          <nav class="-mb-px flex space-x-8" aria-label="Tabs">
            <a href="#" :class="[activeTab === 'myAccount' ? 'border-gray-800 text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300', 'whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm']" @click.prevent="activeTab = 'myAccount'">Mi Cuenta</a>
            <a href="#" :class="[activeTab === 'privacySecurity' ? 'border-gray-800 text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300', 'whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm']" @click.prevent="activeTab = 'privacySecurity'">Privacidad & Seguridad</a>
            <a href="#" :class="[activeTab === 'notifications' ? 'border-gray-800 text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300', 'whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm']" @click.prevent="activeTab = 'notifications'">Notificaciones</a>
            </nav>
        </div>

        <div v-if="activeTab === 'myAccount'" class="mt-8 space-y-6">
          <h3 class="text-lg leading-6 font-medium text-gray-900">Configuración Básica</h3>
          <p class="mt-1 text-sm text-gray-500">Actualiza la información de tu perfil.</p>

          <div>
            <label for="first-name" class="block text-sm font-medium text-gray-700">Nombre</label>
            <div class="mt-1">
              <input id="first-name" name="first-name" type="text" v-model="formData.firstName" autocomplete="given-name" class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-500 focus:border-gray-500 sm:text-sm">
            </div>
          </div>

          <div>
            <label for="last-name" class="block text-sm font-medium text-gray-700">Apellido</label>
            <div class="mt-1">
              <input id="last-name" name="last-name" type="text" v-model="formData.lastName" autocomplete="family-name" class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-500 focus:border-gray-500 sm:text-sm">
            </div>
          </div>

          <div>
            <label for="email-address" class="block text-sm font-medium text-gray-700">Correo Electrónico</label>
            <div class="mt-1">
              <input id="email-address" name="email" type="email" v-model="formData.email" autocomplete="email" class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-500 focus:border-gray-500 sm:text-sm">
            </div>
          </div>

          <div>
            <label for="phone-number" class="block text-sm font-medium text-gray-700">Número de Teléfono</label>
            <div class="mt-1">
              <input id="phone-number" name="phone-number" type="tel" v-model="formData.phoneNumber" autocomplete="tel" class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-500 focus:border-gray-500 sm:text-sm">
            </div>
          </div>

          <div>
            <label for="bio" class="block text-sm font-medium text-gray-700">Sobre mí (Tu biografía)</label>
            <div class="mt-1">
              <textarea id="bio" name="bio" rows="3" v-model="formData.bio" class="shadow-sm focus:ring-gray-500 focus:border-gray-500 mt-1 block w-full sm:text-sm border border-gray-300 rounded-md"></textarea>
              <p class="mt-2 text-sm text-gray-500">{{ formData.bio.length }}/250</p>
            </div>
          </div>

          <div class="pt-5">
            <div class="flex justify-end space-x-3">
              <button type="button" @click="handleCancel" class="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                Cancelar
              </button>
              <button type="submit" @click="handleSave" class="inline-flex justify-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
                Guardar
              </button>
            </div>
          </div>
        </div>

        <div v-else class="mt-8 space-y-6">
          <p class="text-sm text-gray-500">Contenido para la pestaña {{ activeTab }}.</p>
        </div>

      </div>
    </div>
  </div>
</template>

<script>
import { ref, reactive } from 'vue';

export default {
  name: 'UserSettings',
  setup() {
    const activeTab = ref('myAccount'); // Pestaña activa por defecto

    const formData = reactive({
      firstName: 'Jenny',
      lastName: 'Wilson',
      email: 'jenny@example.com',
      phoneNumber: '123-456-7890',
      bio: "Soy un/a desarrollador/a de software apasionado/a por crear experiencias de usuario intuitivas y eficientes. Cuando no estoy programando, disfruto explorando nuevas tecnologías y pasando tiempo al aire libre.",
    });

    const handleSave = () => {
      console.log('Datos guardados:', formData);
      // Aquí iría la lógica para enviar los datos al backend
      // showToast('Perfil actualizado con éxito!', 'success'); // Ejemplo de uso del toast
    };

    const handleCancel = () => {
      console.log('Cancelado.');
      // Lógica para resetear el formulario a su estado original o redirigir
      // Puedes recargar los datos del usuario desde un store si los tienes
    };

    return {
      activeTab,
      formData,
      handleSave,
      handleCancel,
    };
  },
};
</script>

<style scoped>
/* No se necesitan estilos scoped adicionales si todo se maneja con Tailwind */
</style>