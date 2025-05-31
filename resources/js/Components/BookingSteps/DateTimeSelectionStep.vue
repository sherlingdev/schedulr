<template>
  <div class="space-y-6">
    <h3 class="text-xl font-semibold text-gray-900 text-center">2. Selecciona Fecha y Hora</h3>

    <div>
      <label for="booking-date" class="block text-sm font-medium text-gray-700">Fecha</label>
      <input type="date" id="booking-date" v-model="selectedDate"
             class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
             :min="minDate">
    </div>

    <div>
      <label for="booking-time" class="block text-sm font-medium text-gray-700">Hora</label>
      <input type="time" id="booking-time" v-model="selectedTime"
             class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm">
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
        @click="proceedToNextStep"
        :disabled="!selectedDate || !selectedTime"
        :class="['inline-flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white',
                 selectedDate && selectedTime ? 'bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700' : 'bg-gray-400 cursor-not-allowed']"
      >
        Siguiente
      </button>
    </div>
  </div>
</template>

<script>
import { ref, computed } from 'vue';

export default {
  name: 'DateTimeSelectionStep',
  emits: ['next', 'prev', 'datetime-selected'],
  setup(props, { emit }) {
    const selectedDate = ref('');
    const selectedTime = ref('');

    // Calcular la fecha mínima para el input de fecha (hoy o mañana)
    const minDate = computed(() => {
      const today = new Date();
      const year = today.getFullYear();
      const month = String(today.getMonth() + 1).padStart(2, '0');
      const day = String(today.getDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    });

    const proceedToNextStep = () => {
      if (selectedDate.value && selectedTime.value) {
        emit('datetime-selected', { date: selectedDate.value, time: selectedTime.value });
        emit('next');
      }
    };

    return {
      selectedDate,
      selectedTime,
      minDate,
      proceedToNextStep,
    };
  },
};
</script>

<style scoped></style>