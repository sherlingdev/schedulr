<template>
  <div id="app-container" class="flex flex-col flex-grow">
    <router-view />
  </div>
</template>

<script>
export default {
  name: 'App',
  mounted() {
    // console.log('App.vue componente montado y listo para el enrutamiento.');
  },
};
</script>

<style scoped>
#app-container {
  /* font-family: 'Inter', sans-serif; */
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #2c3e50;
  /* min-height: 100vh;
  display: flex;
  flex-direction: column; */
}
</style>