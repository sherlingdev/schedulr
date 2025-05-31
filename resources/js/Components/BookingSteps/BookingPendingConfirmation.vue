<template>
  <div class="flex flex-col items-center justify-center py-8 px-4 text-center">
    <h3 class="text-2xl font-bold text-gray-900 mb-4">
      ¡Tu Cita Ha Sido Solicitada!
    </h3>
    <p class="text-base text-gray-700 mb-6 max-w-md">
      Hemos recibido tu solicitud de cita y está **pendiente de aprobación**.
      Te hemos enviado un correo electrónico con un resumen de los detalles.
      Recibirás otro correo tan pronto como tu cita sea **confirmada** por nuestro equipo.
    </p>

    <button type="button"
            @click="goToDashboard"
            class="mt-4 w-full sm:w-auto inline-flex items-center justify-center px-6 py-3 border border-transparent rounded-md shadow-sm text-base font-medium text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
      Volver al Dashboard
    </button>
  </div>
</template>

<script>
import { defineComponent } from 'vue';
// Si usas Vue Router, importarías el router aquí:
// import { useRouter } from 'vue-router';

export default defineComponent({
  emits: ['reset-wizard'], // Emite un evento para que el padre resetee el wizard
  setup(props, { emit }) {
    // Si usas Vue Router:
    // const router = useRouter();

    const goToDashboard = () => {
      // Si usas Vue Router:
      // router.push('/dashboard');

      // Si no usas Vue Router, o para que el wizard se resetee:
      emit('reset-wizard');
    };

    return {
      goToDashboard,
    };
  },
});
</script>

<style scoped>
/* No se necesitan estilos scoped adicionales si todo se maneja con Tailwind */
</style>