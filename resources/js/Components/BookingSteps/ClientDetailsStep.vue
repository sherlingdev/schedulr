<template>
  <form @submit.prevent="submitDetails" class="space-y-6">
    <div>
      <label for="client-name" class="block text-sm font-medium text-gray-700">
        Nombre Completo
      </label>
      <div class="mt-1">
        <input
          id="client-name"
          name="name"
          type="text"
          autocomplete="name"
          required
          placeholder="Tu nombre completo"
          class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
          v-model="form.name"
        />
      </div>
    </div>

    <div>
      <label for="client-email" class="block text-sm font-medium text-gray-700">
        Correo Electrónico
      </label>
      <div class="mt-1">
        <input
          id="client-email"
          name="email"
          type="email"
          autocomplete="email"
          required
          placeholder="Tu correo electrónico"
          class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
          v-model="form.email"
        />
      </div>
    </div>

    <div>
      <label for="client-phone" class="block text-sm font-medium text-gray-700">
        Número de Teléfono
      </label>
      <div class="mt-1">
        <input
          id="client-phone"
          name="phone"
          type="tel"
          autocomplete="tel"
          required
          placeholder="Ej. +1 809 123 4567"
          class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
          v-model="form.phone"
        />
      </div>
    </div>

    <div class="flex justify-between mt-6">
      <button
        type="button"
        @click="$emit('prev')"
        class="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-300"
      >
        Atrás
      </button>
      <button
        type="submit"
        class="inline-flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700"
      >
        Siguiente
      </button>
    </div>
  </form>
</template>

<script>
import { ref, watch } from 'vue';

export default {
  name: 'ClientDetailsStep',
  props: {
    initialData: {
      type: Object,
      default: () => ({ name: '', email: '', phone: '' })
    }
  },
  emits: ['submit-details', 'prev'],
  setup(props, { emit }) {
    const form = ref({ ...props.initialData });

    // Observar cambios en initialData (ej. si el usuario retrocede y luego avanza)
    watch(() => props.initialData, (newVal) => {
      form.value = { ...newVal };
    }, { deep: true });

    const submitDetails = () => {
      emit('submit-details', form.value);
    };

    return {
      form,
      submitDetails,
    };
  },
};
</script>

<style scoped>
/* No se necesitan estilos específicos aquí, Tailwind CSS lo maneja */
</style>
