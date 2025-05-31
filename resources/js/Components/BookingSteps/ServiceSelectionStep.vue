<template>
  <div class="space-y-6">
    <h3 class="text-xl font-semibold text-gray-900 text-center">1. Selecciona tu Servicio</h3>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div v-for="service in availableServices" :key="service.id"
           @click="selectService(service)"
           :class="['p-4 border rounded-md cursor-pointer transition-all duration-200',
                    selectedService && selectedService.id === service.id ? 'border-gray-800 ring-2 ring-gray-800 bg-gray-50' : 'border-gray-200 hover:border-gray-400 hover:bg-gray-50']">
        <h4 class="font-medium text-gray-900">{{ service.name }}</h4>
        <p class="text-sm text-gray-600">{{ service.description }}</p>
        <div class="flex justify-between items-center mt-2">
          <span class="text-sm font-semibold text-gray-800">${{ service.price.toFixed(2) }}</span>
          <span class="text-xs text-gray-500">{{ service.duration }} min</span>
        </div>
      </div>
      <p v-if="availableServices.length === 0" class="col-span-full text-center text-gray-500 py-4">No hay servicios disponibles.</p>
    </div>

    <div class="flex justify-end mt-6">
      <button
        type="button"
        @click="proceedToNextStep"
        :disabled="!selectedService"
        :class="['inline-flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white',
                 selectedService ? 'bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700' : 'bg-gray-400 cursor-not-allowed']"
      >
        Siguiente
      </button>
    </div>
  </div>
</template>

<script>
import { ref } from 'vue';

export default {
  name: 'ServiceSelectionStep',
  emits: ['next', 'service-selected'],
  setup(props, { emit }) {
    // Datos de servicios de ejemplo (puedes cargarlos desde una API real más adelante)
    const availableServices = ref([
      { id: 1, name: 'Corte de Cabello Masculino', description: 'Corte clásico con lavado y peinado.', duration: 30, price: 25.00 },
      { id: 2, name: 'Tinte de Cabello Completo', description: 'Aplicación de color en todo el cabello.', duration: 90, price: 60.00 },
      { id: 3, name: 'Manicura y Pedicura', description: 'Cuidado completo de manos y pies.', duration: 75, price: 40.00 },
      { id: 4, name: 'Arreglo de Barba', description: 'Recorte, perfilado y acondicionamiento de barba.', duration: 20, price: 15.00 },
      { id: 5, name: 'Peinado para Evento', description: 'Peinado especial para ocasiones.', duration: 60, price: 35.00 },
    ]);

    const selectedService = ref(null);

    const selectService = (service) => {
      selectedService.value = service;
    };

    const proceedToNextStep = () => {
      if (selectedService.value) {
        emit('service-selected', selectedService.value);
        emit('next');
      }
    };

    return {
      availableServices,
      selectedService,
      selectService,
      proceedToNextStep,
    };
  },
};
</script>

<style scoped></style>