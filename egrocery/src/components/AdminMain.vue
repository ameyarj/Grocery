<template>
  <v-app>
    <v-app-bar app color="white" flat>
      <v-badge color="#D5F0DB" dot>
        <v-img src="1.png" contain width="30"></v-img>
      </v-badge>

      <v-toolbar-title class="ml-4">
        <span class="green--text font-weight-bold ml-1">eGrocery</span>
      </v-toolbar-title>

      
      <v-btn class="white--text mx-auto btn btn-success" text to="/">
        <strong>Home</strong>
      </v-btn>
      

      <v-btn icon dark class="ml-2">
      </v-btn>
    </v-app-bar>

    <v-container class="mt-4">
      <v-row>
        <v-col cols="12" sm="6" md="4">
          <v-card @click="goTo('/AdminLogin')" class="text-center">
            <v-img src="admin-logo.png" max-height="auto"></v-img>
            <v-card-title class="mt-2 btn btn-success">Admin Login</v-card-title>
          </v-card>
        </v-col>
        <v-col cols="12" sm="6" md="4">
          <v-card @click="goTo('/SmanagerSignup')" class="text-center">
            <v-img src="smanager-signup-logo.png" max-height="auto"></v-img>
            <v-card-title class="mt-2 btn btn-success">Store Manager Signup</v-card-title>
          </v-card>
        </v-col>
        <v-col cols="12" sm="6" md="4">
          <v-card @click="goTo('/SmanagerLogin')" class="text-center">
            <v-img src="smanager-login-logo.png" max-height="auto"></v-img>
            <v-card-title class="mt-2 btn btn-success">Store Manager Login</v-card-title>
          </v-card>
        </v-col>
      </v-row>
    </v-container>
  </v-app>
</template>

<script>
export default {
  methods: {
    goTo(route) {
      this.$router.push(route);
      this.$router.go();
    },
  },
};
</script>

<style>
.v-toolbar__title {
  font-size: 1.2rem !important;
  display: flex;
  align-items: center;
}

.green--text {
  color: #4CAF50 !important;
}

.font-weight-bold {
  font-weight: bold;
}
</style>
