<template>
  <div class="space-y-6">
    <h3 class="text-xl font-semibold text-gray-900 text-center">4. Confirma tu Cita</h3>

    <div class="bg-gray-50 p-6 rounded-md shadow-sm space-y-4">
      <div class="flex justify-between items-center">
        <span class="text-sm font-medium text-gray-700">Servicio:</span>
        <span class="text-base font-semibold text-gray-900">{{ bookingData.service ? bookingData.service.name : 'N/A' }}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-sm font-medium text-gray-700">Fecha:</span>
        <span class="text-base font-semibold text-gray-900">{{ bookingData.date || 'N/A' }}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-sm font-medium text-gray-700">Hora:</span>
        <span class="text-base font-semibold text-gray-900">{{ bookingData.time || 'N/A' }}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-sm font-medium text-gray-700">Nombre:</span>
        <span class="text-base font-semibold text-gray-900">{{ bookingData.clientName || 'N/A' }}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-sm font-medium text-gray-700">Email:</span>
        <span class="text-base font-semibold text-gray-900">{{ bookingData.clientEmail || 'N/A' }}</span>
      </div>
      <div class="flex justify-between items-center">
        <span class="text-sm font-medium text-gray-700">Teléfono:</span>
        <span class="text-base font-semibold text-gray-900">{{ bookingData.clientPhone || 'N/A' }}</span>
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
        type="button"
        @click="$emit('confirm-booking')"
        class="inline-flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700"
      >
        Confirmar Cita
      </button>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue';

export default {
  name: 'ConfirmationStep',
  props: {
    bookingData: {
      type: Object,
      required: true,
    },
  },
  emits: ['prev', 'confirm-booking'],
  setup(props, { emit }) {
    return {};
  },
};
</script>

<style scoped></style>