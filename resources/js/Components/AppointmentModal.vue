<template>
  <transition name="modal-fade">
    <div v-if="isVisible" class="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div class="fixed inset-0 bg-gray-900 bg-opacity-50" @click="close"></div>

      <div class="bg-white rounded-lg shadow-xl w-full max-w-md mx-auto z-10 overflow-hidden" role="dialog" aria-modal="true" :aria-labelledby="modalTitleId">
        <div class="px-6 py-4 flex items-center justify-between border-b border-gray-100">
          <h3 :id="modalTitleId" class="text-lg font-semibold text-gray-900">{{ modalTitle }}</h3>
          <button @click="close" class="text-gray-400 hover:text-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-300 rounded-md">
            <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
          </button>
        </div>

        <div class="p-6 space-y-4">
          <div>
            <label for="client-name" class="block text-sm font-medium text-gray-700">Nombre del Cliente</label>
            <input type="text" id="client-name" v-model="form.clientName"
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                   placeholder="Nombre completo del cliente">
          </div>
          <div>
            <label for="client-email" class="block text-sm font-medium text-gray-700">Email del Cliente</label>
            <input type="email" id="client-email" v-model="form.clientEmail"
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                   placeholder="correo@ejemplo.com">
          </div>
          <div>
            <label for="client-phone" class="block text-sm font-medium text-gray-700">Teléfono del Cliente</label>
            <input type="tel" id="client-phone" v-model="form.clientPhone"
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                   placeholder="Ej. +1 809 123 4567">
          </div>

          <div>
            <label for="appointment-service" class="block text-sm font-medium text-gray-700">Servicio</label>
            <select id="appointment-service" v-model="form.serviceName"
                    class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm">
              <option value="">Selecciona un servicio</option>
              <option v-for="service in availableServices" :key="service.id" :value="service.name">
                {{ service.name }} (${{ service.price.toFixed(2) }})
              </option>
            </select>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label for="appointment-date" class="block text-sm font-medium text-gray-700">Fecha</label>
              <input type="date" id="appointment-date" v-model="form.date"
                     class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                     :min="minDate">
            </div>
            <div>
              <label for="appointment-time" class="block text-sm font-medium text-gray-700">Hora</label>
              <input type="time" id="appointment-time" v-model="form.time"
                     class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm">
            </div>
          </div>

          <div>
            <label for="appointment-status" class="block text-sm font-medium text-gray-700">Estado de la Cita</label>
            <select id="appointment-status" v-model="form.status"
                    class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm">
              <option value="Pendiente">Pendiente</option>
              <option value="Confirmada">Confirmada</option>
              <option value="Completada">Completada</option>
              <option value="Cancelada">Cancelada</option>
            </select>
          </div>
        </div>

        <div class="px-6 py-4 bg-gray-50 border-t border-gray-100 flex justify-end space-x-3">
          <button @click="close"
                  class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-300">
            Cancelar
          </button>
          <button @click="saveAppointment"
                  class="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700">
            {{ isEditing ? 'Actualizar Cita' : 'Crear Cita' }}
          </button>
        </div>
      </div>
    </div>
  </transition>
</template>

<script>
import { ref, reactive, watch, computed } from 'vue';

export default {
  name: 'AppointmentModal',
  props: {
    isVisible: {
      type: Boolean,
      default: false,
    },
    editingAppointment: { // Prop para la cita a editar
      type: Object,
      default: null,
    },
  },
  emits: ['close', 'save'],
  setup(props, { emit }) {
    const form = reactive({
      id: null,
      clientName: '',
      clientEmail: '',
      clientPhone: '',
      serviceName: '', // Nombre del servicio seleccionado
      date: '',
      time: '',
      status: 'Pendiente',
    });

    // Datos de servicios disponibles para el dropdown (pueden venir de una prop si son dinámicos)
    const availableServices = ref([
      { id: 1, name: 'Corte de Cabello Masculino', price: 25.00 },
      { id: 2, name: 'Tinte de Cabello Completo', price: 60.00 },
      { id: 3, name: 'Manicura y Pedicura', price: 40.00 },
      { id: 4, name: 'Arreglo de Barba', price: 15.00 },
      { id: 5, name: 'Peinado para Evento', price: 35.00 },
    ]);

    const isEditing = computed(() => !!props.editingAppointment);

    const modalTitle = computed(() =>
      isEditing.value ? 'Editar Cita' : 'Crear Nueva Cita'
    );

    const modalTitleId = computed(() => `modal-title-${Date.now()}`);

    // Calcular la fecha mínima para el input de fecha (hoy)
    const minDate = computed(() => {
      const today = new Date();
      const year = today.getFullYear();
      const month = String(today.getMonth() + 1).padStart(2, '0');
      const day = String(today.getDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    });

    watch([() => props.isVisible, () => props.editingAppointment], ([newIsVisible, newEditingAppointment]) => {
      if (newIsVisible) {
        if (newEditingAppointment) {
          // Modo edición: cargar datos de la cita existente
          form.id = newEditingAppointment.id;
          form.clientName = newEditingAppointment.clientName || '';
          form.clientEmail = newEditingAppointment.clientEmail || '';
          form.clientPhone = newEditingAppointment.clientPhone || '';
          form.serviceName = newEditingAppointment.serviceName || '';
          form.date = newEditingAppointment.date || '';
          form.time = newEditingAppointment.time || '';
          form.status = newEditingAppointment.status || 'Pendiente';
        } else {
          // Modo creación: resetear el formulario
          form.id = null;
          form.clientName = '';
          form.clientEmail = '';
          form.clientPhone = '';
          form.serviceName = '';
          form.date = '';
          form.time = '';
          form.status = 'Pendiente';
        }
      }
    }, { immediate: true });

    const close = () => {
      emit('close');
    };

    const saveAppointment = () => {
      emit('save', { ...form });
      close();
    };

    return {
      form,
      availableServices,
      close,
      saveAppointment,
      isEditing,
      modalTitle,
      modalTitleId,
      minDate,
    };
  },
};
</script>

<style scoped>
/* Estilos para las transiciones del modal */
.modal-fade-enter-active, .modal-fade-leave-active {
  transition: opacity 0.3s ease;
}
.modal-fade-enter-from, .modal-fade-leave-to {
  opacity: 0;
}
</style>