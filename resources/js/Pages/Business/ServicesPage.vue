<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <h1 class="text-3xl font-bold text-gray-900">Servicios</h1>
      <div class="flex items-center space-x-3">
        <div class="relative">
          <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <svg class="h-5 w-5 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
          </div>
          <input
            type="text"
            placeholder="Buscar..."
            class="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-400 focus:outline-none focus:ring-gray-300 focus:border-gray-300 sm:text-sm"
          />
        </div>

        <button type="button" class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-300">
          <svg class="h-4 w-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zm0 4a1 1 0 011-1h16a1 1 0 011 1v12a1 1 0 01-1 1H4a1 1 0 01-1-1V8zm5 3H7m5-3h-2m8 4h-2"></path></svg>
          Filtrar
        </button>

        <button @click="openCreateModal" type="button" class="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700">
          <svg class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path></svg>
          Nuevo Servicio
        </button>
      </div>
    </div>

    <div class="bg-white shadow-sm rounded-lg overflow-hidden">
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                <input type="checkbox" class="h-4 w-4 text-gray-800 border-gray-300 rounded" />
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Nombre
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Categoría
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Duración
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Precio
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Estado
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Acciones
              </th>
            </tr>
          </thead>
          <tbody class="bg-white divide-y divide-gray-200">
            <tr v-for="service in services" :key="service.id">
              <td class="px-6 py-4 whitespace-nowrap">
                <input type="checkbox" class="h-4 w-4 text-gray-800 border-gray-300 rounded" />
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                {{ service.name }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ service.category || 'N/A' }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ service.duration ? `${service.duration} min` : 'N/A' }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ service.price ? `$${service.price.toFixed(2)}` : 'N/A' }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <span :class="{'px-2 inline-flex text-xs leading-5 font-semibold rounded-full': true,
                               'bg-green-100 text-green-800': service.status === 'Activo',
                               'bg-yellow-100 text-yellow-800': service.status === 'Pendiente',
                               'bg-red-100 text-red-800': service.status === 'Cancelado'}">
                  {{ service.status }}
                </span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                <div class="flex space-x-2">
                  <button @click="openEditModal(service)" class="text-gray-600 hover:text-gray-900" title="Editar">
                    <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg>
                  </button>
                  <button class="text-gray-600 hover:text-gray-900" title="Eliminar">
                    <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                  </button>
                  <button class="text-gray-600 hover:text-gray-900" title="Descargar">
                    <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <ServiceModal
      :is-visible="showServiceModal"
      :editing-service="selectedService"
      @close="closeServiceModal"
      @save="handleSaveService"
    />
  </div>
</template>

<script>
import { ref } from 'vue';
import ServiceModal from '../../Components/ServiceModal.vue'; // Importa el componente del modal (nombre actualizado)

export default {
  name: 'ServicesPage',
  components: {
    ServiceModal, // Registra el componente (nombre actualizado)
  },
  setup() {
    const showServiceModal = ref(false); // Controla la visibilidad del modal
    const selectedService = ref(null); // Almacena el servicio que se está editando (null para creación)

    // Datos de ejemplo para la tabla de servicios
    const services = ref([
      { id: 1, name: 'Corte de Cabello Masculino', category: 'Cabello', duration: 30, price: 25.00, status: 'Activo', createdAt: '2024-05-20', description: 'Corte clásico para hombres con lavado y peinado.', schedule: 'L-V 9am-6pm' },
      { id: 2, name: 'Tinte de Raíz', category: 'Cabello', duration: 90, price: 50.00, status: 'Pendiente', createdAt: '2024-05-18', description: 'Retoque de color en las raíces.', schedule: 'L-S 10am-7pm' },
      { id: 3, name: 'Manicura Clásica', category: 'Uñas', duration: 45, price: 15.00, status: 'Activo', createdAt: '2024-05-15', description: 'Limado, cutículas y esmaltado tradicional.', schedule: 'M-S 9am-5pm' },
      { id: 4, name: 'Arreglo de Barba', category: 'Barba', duration: 20, price: 10.00, status: 'Activo', createdAt: '2024-05-10', description: 'Recorte y perfilado de barba con productos.', schedule: 'L-V 9am-6pm' },
      { id: 5, name: 'Masaje Capilar', category: 'Tratamientos', duration: 30, price: 20.00, status: 'Inactivo', createdAt: '2024-05-05', description: 'Tratamiento relajante con masaje y ampolla nutritiva.', schedule: 'J-S 11am-4pm' },
    ]);

    // Función para abrir el modal en modo creación
    const openCreateModal = () => {
      selectedService.value = null; // Asegura que el modal esté en modo creación
      showServiceModal.value = true;
    };

    // Función para abrir el modal en modo edición
    const openEditModal = (service) => {
      selectedService.value = service; // Pasa el servicio a editar al modal
      showServiceModal.value = true;
    };

    // Función para cerrar el modal
    const closeServiceModal = () => {
      showServiceModal.value = false;
      selectedService.value = null; // Limpiar el servicio seleccionado al cerrar
    };

    // Función para manejar el guardado/actualización desde el modal
    const handleSaveService = (serviceData) => {
      if (serviceData.id) {
        // Es una actualización
        const index = services.value.findIndex(s => s.id === serviceData.id);
        if (index !== -1) {
          // Actualiza los campos del servicio existente
          services.value[index].name = serviceData.name;
          services.value[index].description = serviceData.description;
          services.value[index].duration = serviceData.duration;
          services.value[index].price = serviceData.price;
          services.value[index].category = serviceData.category;
          services.value[index].status = serviceData.status;
          services.value[index].schedule = serviceData.schedule;
          // En una aplicación real, aquí harías una llamada a tu API para actualizar el servicio en la base de datos.
        }
      } else {
        // Es una creación
        const newId = services.value.length > 0 ? Math.max(...services.value.map(s => s.id)) + 1 : 1;
        const newService = {
          ...serviceData, // Copia todos los datos del formulario
          id: newId,
          createdAt: new Date().toISOString().split('T')[0], // Fecha actual
        };
        services.value.push(newService);
        // En una aplicación real, aquí harías una llamada a tu API para guardar el servicio en la base de datos.
      }
    };

    return {
      showServiceModal,
      selectedService,
      services,
      openCreateModal,
      openEditModal,
      closeServiceModal,
      handleSaveService,
    };
  },
};
</script>

<style scoped>
/* No se necesitan estilos específicos aquí, Tailwind CSS lo maneja */
</style>
