<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <h1 class="text-3xl font-bold text-gray-900">Citas</h1>
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

        <button @click="openCreateAppointmentModal" type="button" class="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-gray-800 hover:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-700">
          <svg class="h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path></svg>
          Nueva Cita
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
                Cliente
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Servicio
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Fecha
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Hora
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
            <tr v-for="appointment in appointments" :key="appointment.id">
              <td class="px-6 py-4 whitespace-nowrap">
                <input type="checkbox" class="h-4 w-4 text-gray-800 border-gray-300 rounded" />
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                {{ appointment.clientName }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ appointment.serviceName }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ appointment.date }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                {{ appointment.time }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <span :class="{'px-2 inline-flex text-xs leading-5 font-semibold rounded-full': true,
                               'bg-green-100 text-green-800': appointment.status === 'Confirmada',
                               'bg-yellow-100 text-yellow-800': appointment.status === 'Pendiente',
                               'bg-blue-100 text-blue-800': appointment.status === 'Completada',
                               'bg-red-100 text-red-800': appointment.status === 'Cancelada'}">
                  {{ appointment.status }}
                </span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                <div class="flex space-x-2">
                  <button @click="openEditAppointmentModal(appointment)" class="text-gray-600 hover:text-gray-900" title="Editar">
                    <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path></svg>
                  </button>
                  <button class="text-gray-600 hover:text-gray-900" title="Eliminar">
                    <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                  </button>
                  <button class="text-gray-600 hover:text-gray-900" title="Detalles">
                    <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <AppointmentModal
      :is-visible="showAppointmentModal"
      :editing-appointment="selectedAppointment"
      @close="closeAppointmentModal"
      @save="handleSaveAppointment"
    />
  </div>
</template>

<script>
import { ref } from 'vue';
import AppointmentModal from '../../Components/AppointmentModal.vue'; // Necesitaremos crear este modal

export default {
  name: 'AppointmentsPage',
  components: {
    AppointmentModal,
  },
  setup() {
    const showAppointmentModal = ref(false);
    const selectedAppointment = ref(null); // Para edición

    // Datos de ejemplo para la tabla de citas
    const appointments = ref([
      { id: 1, clientName: 'Juan Pérez', serviceName: 'Corte de Cabello Masculino', date: '2024-06-01', time: '10:00 AM', status: 'Confirmada' },
      { id: 2, clientName: 'María García', serviceName: 'Tinte de Cabello Completo', date: '2024-06-01', time: '11:30 AM', status: 'Pendiente' },
      { id: 3, clientName: 'Carlos López', serviceName: 'Manicura Clásica', date: '2024-06-02', time: '09:00 AM', status: 'Completada' },
      { id: 4, clientName: 'Ana Rodríguez', serviceName: 'Arreglo de Barba', date: '2024-06-02', time: '02:00 PM', status: 'Cancelada' },
    ]);

    const openCreateAppointmentModal = () => {
      selectedAppointment.value = null; // Modo creación
      showAppointmentModal.value = true;
    };

    const openEditAppointmentModal = (appointment) => {
      selectedAppointment.value = appointment; // Modo edición
      showAppointmentModal.value = true;
    };

    const closeAppointmentModal = () => {
      showAppointmentModal.value = false;
      selectedAppointment.value = null;
    };

    const handleSaveAppointment = (appointmentData) => {
      if (appointmentData.id) {
        // Lógica para actualizar una cita existente
        const index = appointments.value.findIndex(a => a.id === appointmentData.id);
        if (index !== -1) {
          Object.assign(appointments.value[index], appointmentData);
          // Aquí harías la llamada a la API para actualizar la cita
        }
      } else {
        // Lógica para crear una nueva cita
        const newId = appointments.value.length > 0 ? Math.max(...appointments.value.map(a => a.id)) + 1 : 1;
        const newAppointment = { ...appointmentData, id: newId };
        appointments.value.push(newAppointment);
        // Aquí harías la llamada a la API para guardar la nueva cita
      }
    };

    return {
      appointments,
      showAppointmentModal,
      selectedAppointment,
      openCreateAppointmentModal,
      openEditAppointmentModal,
      closeAppointmentModal,
      handleSaveAppointment,
    };
  },
};
</script>

<style scoped></style>