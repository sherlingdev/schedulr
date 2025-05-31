<template>
  <div class="space-y-6">
    <h1 class="text-3xl font-bold text-gray-900">Bienvenido al Dashboard</h1>
    <p class="text-gray-700">Aquí puedes ver un resumen de tus actividades y estadísticas.</p>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      <div class="bg-white p-6 rounded-lg shadow-sm">
        <h2 class="text-xl font-semibold text-gray-800">Citas de Hoy</h2>
        <p class="mt-2 text-gray-600">5 citas programadas para hoy.</p>
      </div>
      <div class="bg-white p-6 rounded-lg shadow-sm">
        <h2 class="text-xl font-semibold text-gray-800">Servicios Activos</h2>
        <p class="mt-2 text-gray-600">12 servicios disponibles.</p>
      </div>
      <div class="bg-white p-6 rounded-lg shadow-sm">
        <h2 class="text-xl font-semibold text-gray-800">Ingresos del Mes</h2>
        <p class="mt-2 text-gray-600">$1,500.00 hasta ahora.</p>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'DashboardHome',
};
</script>