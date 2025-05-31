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
            <label for="service-name" class="block text-sm font-medium text-gray-700">Nombre del Servicio</label>
            <input type="text" id="service-name" v-model="form.name"
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                   placeholder="Ej. Corte de Cabello Masculino">
          </div>
          <div>
            <label for="service-description" class="block text-sm font-medium text-gray-700">Descripción</label>
            <textarea id="service-description" v-model="form.description" rows="3"
                      class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                      placeholder="Detalles sobre el tipo de corte, productos incluidos, etc."></textarea>
          </div>
          <div>
            <label for="service-duration" class="block text-sm font-medium text-gray-700">Duración Estimada (minutos)</label>
            <input type="number" id="service-duration" v-model.number="form.duration"
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                   placeholder="Ej. 30">
          </div>
          <div>
            <label for="service-price" class="block text-sm font-medium text-gray-700">Precio ($)</label>
            <input type="number" id="service-price" v-model.number="form.price" step="0.01"
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                   placeholder="Ej. 25.00">
          </div>
          <div>
            <label for="service-category" class="block text-sm font-medium text-gray-700">Categoría</label>
            <select id="service-category" v-model="form.category"
                    class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm">
              <option value="">Selecciona una categoría</option>
              <option value="Cabello">Cabello</option>
              <option value="Barba">Barba</option>
              <option value="Uñas">Uñas</option>
              <option value="Tratamientos">Tratamientos</option>
              <option value="Otros">Otros</option>
            </select>
          </div>
          <div>
            <label for="service-status" class="block text-sm font-medium text-gray-700">Estado</label>
            <select id="service-status" v-model="form.status"
                    class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm">
              <option value="Activo">Activo</option>
              <option value="Inactivo">Inactivo</option>
              <option value="Pendiente">Pendiente</option>
            </select>
          </div>
          <div>
            <label for="service-schedule" class="block text-sm font-medium text-gray-700">Horario de Servicio (ej. L-V 9am-6pm)</label>
            <input type="text" id="service-schedule" v-model="form.schedule"
                   class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
                   placeholder="Ej. Lunes a Viernes 9:00 AM - 6:00 PM">
          </div>
        </div>

        <div class="px-6 py-4 bg-gray-50 border-t border-gray-100 flex justify-end space-x-3">
          <button @click="close"
                  class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-300">
            Cancelar
          </button>
          <button @click="saveService"
                  class="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700">
            {{ isEditing ? 'Actualizar Servicio' : 'Guardar Servicio' }}
          </button>
        </div>
      </div>
    </div>
  </transition>
</template>

<script>
import { ref, reactive, watch, computed } from 'vue';

export default {
  name: 'ServiceModal', // Nombre del componente actualizado
  props: {
    isVisible: {
      type: Boolean,
      default: false,
    },
    editingService: { // Nueva prop para el servicio a editar
      type: Object,
      default: null, // Si es null, estamos creando; si es un objeto, estamos editando.
    },
  },
  emits: ['close', 'save'], // 'save' ahora manejará tanto la creación como la actualización
  setup(props, { emit }) {
    const form = reactive({
      id: null, // Se usará solo en modo edición
      name: '',
      description: '',
      duration: null,
      price: null,
      category: '',
      status: 'Activo',
      schedule: '',
    });

    // Determina si estamos en modo edición
    const isEditing = computed(() => !!props.editingService);

    // Título del modal dinámico
    const modalTitle = computed(() =>
      isEditing.value ? 'Editar Servicio de Peluquería' : 'Crear Nuevo Servicio de Peluquería'
    );

    // Para la accesibilidad, genera un ID único para el título
    const modalTitleId = computed(() => `modal-title-${Date.now()}`);


    // Observa 'isVisible' y 'editingService' para resetear/cargar el formulario
    watch([() => props.isVisible, () => props.editingService], ([newIsVisible, newEditingService]) => {
      if (newIsVisible) {
        if (newEditingService) {
          // Modo edición: cargar datos del servicio existente
          form.id = newEditingService.id;
          form.name = newEditingService.name || '';
          form.description = newEditingService.description || '';
          form.duration = newEditingService.duration || null;
          form.price = newEditingService.price || null;
          form.category = newEditingService.category || '';
          form.status = newEditingService.status || 'Activo';
          form.schedule = newEditingService.schedule || '';
        } else {
          // Modo creación: resetear el formulario
          form.id = null;
          form.name = '';
          form.description = '';
          form.duration = null;
          form.price = null;
          form.category = '';
          form.status = 'Activo';
          form.schedule = '';
        }
      }
    }, { immediate: true }); // 'immediate: true' para que se ejecute al inicio si el modal ya está visible

    const close = () => {
      emit('close');
    };

    const saveService = () => {
      // Emitir el formulario completo, incluyendo el ID si es una edición.
      // El componente padre (ServicesPage) se encargará de determinar si es crear o actualizar
      emit('save', { ...form });
      close();
    };

    return {
      form,
      close,
      saveService,
      isEditing,
      modalTitle,
      modalTitleId
    };
  },
};
</script>

<style scoped>
/* Estilos para las transiciones del modal (opcional, pero mejora la UX) */
.modal-fade-enter-active, .modal-fade-leave-active {
  transition: opacity 0.3s ease;
}
.modal-fade-enter-from, .modal-fade-leave-to {
  opacity: 0;
}
</style>
