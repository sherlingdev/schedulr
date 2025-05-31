<template>
  <div class="bg-gray-50 min-h-screen font-sans antialiased">
    <header class="bg-white shadow-sm py-4 px-4 sm:px-6 lg:px-8 rounded-b-lg">
      <nav class="w-full mx-auto flex justify-between items-center max-w-7xl">
        <div class="text-2xl font-bold text-gray-800">Schedulr</div>

        <div class="hidden md:flex space-x-6">
          <!-- <a href="#" class="text-gray-700 hover:text-indigo-700 font-medium rounded-md px-3 py-2 transition-colors duration-200">About</a>
          <a href="#" class="text-gray-700 hover:text-indigo-700 font-medium rounded-md px-3 py-2 transition-colors duration-200">Pricing</a>
          <a href="#" class="text-gray-700 hover:text-indigo-700 font-medium rounded-md px-3 py-2 transition-colors duration-200">Support</a>
          <a href="#" class="text-gray-700 hover:text-indigo-700 font-medium rounded-md px-3 py-2 transition-colors duration-200">Watch Tutorials</a> -->
        </div>

        <div class="flex items-center space-x-4">
          <router-link to="/login" class="text-gray-700 hover:text-indigo-700 font-semibold rounded-md px-3 py-2 transition-colors duration-200">Login</router-link>
          <router-link to="/register" class="bg-gray-800 hover:bg-gray-700 text-white font-semibold py-2 px-5 rounded-lg shadow-md transition-colors duration-200">Signup</router-link>
        </div>
      </nav>
    </header>

    <section class="py-16 md:py-24 lg:py-32 bg-gray-50 text-center">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <span class="inline-block bg-indigo-100 text-indigo-700 py-1 px-4 rounded-full text-sm font-semibold mb-6 shadow-sm">
          Just launched : Beta V1.0
        </span>
        <h1 class="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-gray-900 mb-6 leading-tight">
          Build and Deploy Your Backend <br class="hidden sm:block">
          Code with Ease
        </h1>
        <p class="text-lg md:text-xl text-gray-700 mb-10 max-w-3xl mx-auto">
          Skip the complexity of backend development. Instantly generate, test, and
          deploy APIs with AI - no hassle, no deep coding required.
        </p>
        <div class="flex flex-col sm:flex-row justify-center space-y-4 sm:space-y-0 sm:space-x-4">
          <button class="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-3 px-8 rounded-lg shadow-lg transform hover:scale-105 transition-all duration-300">
            Generate Backend
          </button>
          <button class="bg-white hover:bg-gray-100 text-gray-800 font-semibold py-3 px-8 rounded-lg shadow-md border border-gray-300 transform hover:scale-105 transition-all duration-300">
            Watch Demo
          </button>
        </div>
        <div class="mt-16">
          <img
            src="https://placehold.co/1000x500/F3F4F6/1F2937?text=Backend+Interface"
            alt="Backend Interface"
            class="mx-auto rounded-xl shadow-2xl border-4 border-white transform hover:scale-102 transition-transform duration-300"
          >
        </div>
      </div>
    </section>

    <section class="py-16 md:py-24 bg-white">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 grid md:grid-cols-2 gap-12 items-center">
        <div>
          <h2 class="text-3xl sm:text-4xl font-bold text-gray-900 mb-6 leading-tight">
            Everything You Need to Build, Scale, <br class="hidden sm:block">
            and Automate Your Backend
          </h2>
          <p class="text-lg text-gray-700 mb-4">
            Backend.IM simplifies backend development with AI-powered code generation,
            authentication setup, database management, and error handling—all in one place.
          </p>
          <p class="text-lg text-gray-700">
            Generate, customize, and deploy backend APIs effortlessly.
          </p>
        </div>
        <div>
          <img
            src="https://placehold.co/600x400/F3F4F6/1F2937?text=Backend+Features"
            alt="Backend Features Overview"
            class="rounded-xl shadow-lg transform hover:scale-102 transition-transform duration-300"
          >
        </div>
      </div>
    </section>

    <section class="py-16 md:py-24 bg-gray-50">
      <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 grid md:grid-cols-2 gap-12 items-center">
        <div class="md:order-1">
          <img
            src="https://placehold.co/600x400/F3F4F6/1F2937?text=Mobile+Experience"
            alt="Optimized Mobile Experience"
            class="rounded-xl shadow-lg transform hover:scale-102 transition-transform duration-300"
          >
        </div>
        <div class="md:order-2">
          <h2 class="text-3xl sm:text-4xl font-bold text-gray-900 mb-6 leading-tight">
            A Fully Optimized Desktop and Mobile Experience
          </h2>
          <p class="text-lg text-gray-700 mb-4">
            Whether on your laptop or phone, Backend.IM offers a seamless experience.
            Build, test, and manage your backend easily, anytime, anywhere.
          </p>
          <div class="mt-6">
            <h3 class="text-xl font-semibold text-indigo-700 mb-2">Build and Manage Your Backend Anywhere</h3>
            <p class="text-gray-700">Seamlessly switch between desktop and mobile. Backend.IM adapts to your workflow.</p>
          </div>
        </div>
      </div>
    </section>

    <section class="py-16 bg-white text-center">
      <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <h2 class="text-3xl sm:text-4xl font-bold text-gray-900 mb-8">
          Trusted by Developers, Loved for Speed and Simplicity
        </h2>
        <p class="text-lg text-gray-700 mb-10">
          Discover how Backend.IM is transforming backend development, saving time and making API creation incredibly simple.
        </p>
        <button class="bg-white hover:bg-gray-100 text-gray-800 font-semibold py-3 px-8 rounded-lg shadow-md border border-gray-300 transform hover:scale-105 transition-all duration-300">
          More User Stories
        </button>
      </div>
    </section>

    <footer class="bg-gray-900 py-8 text-center text-gray-400 text-sm rounded-t-lg">
      <div class="w-full mx-auto px-4 sm:px-6 lg:px-8 max-w-7xl">
        <p>&copy; {{ new Date().getFullYear() }} Backend.IM. All rights reserved.</p>
        <div class="mt-4 space-x-6">
          <a href="#" class="hover:text-white transition-colors duration-200">Privacy Policy</a>
          <a href="#" class="hover:text-white transition-colors duration-200">Terms of Service</a>
          <a href="#" class="hover:text-white transition-colors duration-200">Contact</a>
        </div>
      </div>
    </footer>
  </div>
</template>

<script>
export default {
  name: 'LandingPage',
  mounted() {
    console.log('LandingPage.vue mounted.');
  }
};
</script>

<style scoped>
/* No se necesitan estilos específicos aquí si todo se maneja con Tailwind CSS */
</style>