<template>
  <div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-xl">
      <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
        Agenda tu cita de peluquería
      </h2>
      <p class="mt-2 text-center text-sm text-gray-600">
        Sigue los pasos para seleccionar tu servicio y horario.
      </p>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-xl">
      <div class="bg-white py-8 px-4 shadow-sm sm:rounded-lg sm:px-10">
        <div v-if="currentStep < steps.length -1" class="flex justify-between mb-8 px-0 sm:px-4">
          <div v-for="(stepItem, index) in visibleSteps" :key="index"
               :class="['flex flex-col items-center flex-1 min-w-0',
                        currentStep === index ? 'text-gray-900' : 'text-gray-500']">
            <div :class="['w-8 h-8 rounded-full flex items-center justify-center mb-1',
                          currentStep === index ? 'bg-gray-800 text-white' : 'bg-gray-200 text-gray-600']">
              {{ index + 1 }}
            </div>
            <span class="hidden sm:block text-center text-xs sm:text-sm whitespace-normal">{{ stepItem.name }}</span>
            <span class="block sm:hidden text-center text-xs whitespace-normal">{{ stepItem.shortName }}</span>
          </div>
        </div>

        <component :is="currentStepComponent"
                   v-bind="currentStepProps"
                   @prev="handlePrevStep"
                   @service-selected="handleServiceSelected"
                   @datetime-selected="handleDateTimeSelected"
                   @submit-details="handleSubmitDetails"
                   @confirm-booking="handleConfirmBooking"
                   @reset-wizard="handleResetWizard" ></component>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, reactive, computed, markRaw } from 'vue';
import ServiceSelectionStep from '../../Components/BookingSteps/ServiceSelectionStep.vue';
import DateTimeSelectionStep from '../../Components/BookingSteps/DateTimeSelectionStep.vue';
import ClientDetailsStep from '../../Components/BookingSteps/ClientDetailsStep.vue';
import ConfirmationStep from '../../Components/BookingSteps/ConfirmationStep.vue';
// Importa el nuevo componente
import BookingPendingConfirmation from '../../Components/BookingSteps/BookingPendingConfirmation.vue';

export default {
  name: 'ScheduleServiceWizard',
  components: {
    ServiceSelectionStep: markRaw(ServiceSelectionStep),
    DateTimeSelectionStep: markRaw(DateTimeSelectionStep),
    ClientDetailsStep: markRaw(ClientDetailsStep),
    ConfirmationStep: markRaw(ConfirmationStep),
    BookingPendingConfirmation: markRaw(BookingPendingConfirmation), // Registra el nuevo componente
  },
  setup() {
    const currentStep = ref(0); // 0-indexed
    const bookingData = reactive({
      service: null,
      date: null,
      time: null,
      clientName: '',
      clientEmail: '',
      clientPhone: '',
    });

    const steps = [
      { name: 'Seleccionar Servicio', shortName: 'Servicio', component: 'ServiceSelectionStep' },
      { name: 'Fecha y Hora', shortName: 'Fecha/Hora', component: 'DateTimeSelectionStep' },
      { name: 'Tus Datos', shortName: 'Datos', component: 'ClientDetailsStep' },
      { name: 'Confirmación', shortName: 'Confirmar', component: 'ConfirmationStep' },
      { name: 'Estado de Cita', shortName: 'Estado', component: 'BookingPendingConfirmation' }, // Nuevo paso final
    ];

    // Computed property para mostrar los pasos "visibles" en el indicador
    const visibleSteps = computed(() => {
      // Muestra solo los pasos 1 a 4 en el indicador superior
      return steps.slice(0, 4);
    });

    const currentStepComponent = computed(() => {
      return steps[currentStep.value].component;
    });

    const currentStepProps = computed(() => {
      switch (steps[currentStep.value].component) {
        case 'ServiceSelectionStep':
          return {};
        case 'DateTimeSelectionStep':
          return {
            selectedService: bookingData.service
          };
        case 'ClientDetailsStep':
          return {
            initialData: {
              name: bookingData.clientName,
              email: bookingData.clientEmail,
              phone: bookingData.clientPhone
            }
          };
        case 'ConfirmationStep':
          return {
            bookingData: bookingData
          };
        case 'BookingPendingConfirmation': // Si es el nuevo paso final
          return {
            // Podrías pasar datos de la cita si el mensaje los necesita
            // bookingData: bookingData
          };
        default:
          return {};
      }
    });

    const advanceStep = () => {
      if (currentStep.value < steps.length - 1) {
        currentStep.value++;
      }
    };

    const handlePrevStep = () => {
      if (currentStep.value > 0) {
        currentStep.value--;
      }
    };

    const handleServiceSelected = (service) => {
      bookingData.service = service;
      advanceStep();
    };

    const handleDateTimeSelected = ({ date, time }) => {
      bookingData.date = date;
      bookingData.time = time;
      advanceStep();
    };

    const handleSubmitDetails = ({ name, email, phone }) => {
      bookingData.clientName = name;
      bookingData.clientEmail = email;
      bookingData.clientPhone = phone;
      advanceStep();
    };

    const handleConfirmBooking = () => {
      console.log('Cita Solicitada:', bookingData);
      // Aquí iría la llamada al backend para guardar la cita real
      // Por ejemplo, con un `axios.post('/api/bookings', bookingData)`

      // Una vez que la solicitud al backend sea exitosa:
      advanceStep(); // Avanza al nuevo paso de BookingPendingConfirmation
    };

    const handleResetWizard = () => {
      currentStep.value = 0; // Resetear el wizard al primer paso
      // Limpiar los datos de reserva
      bookingData.service = null;
      bookingData.date = null;
      bookingData.time = null;
      bookingData.clientName = '';
      bookingData.clientEmail = '';
      bookingData.clientPhone = '';
      // Aquí podrías redirigir al dashboard si usas Vue Router:
      // useRouter().push('/dashboard');
    };

    return {
      currentStep,
      steps,
      visibleSteps, // Exponer para el template
      bookingData,
      currentStepComponent,
      currentStepProps,
      handlePrevStep,
      handleServiceSelected,
      handleDateTimeSelected,
      handleSubmitDetails,
      handleConfirmBooking,
      handleResetWizard,
    };
  },
};
</script>

<style scoped>
/* Estilos para el wizard, si son necesarios más allá de Tailwind */
</style>