<template>
  <div>
    <Navbar />
    <v-app class="background-image">
      <v-container fill-height>
        <v-row justify="center" align="center">
          <v-col cols="12" sm="8" md="6">
            <v-card class="elevation-12 card-background mx-auto rounded-xl">
              <v-card-title class=" darken-2 green--text justify-center">
                <h2 class="mb-0">Admin Login</h2>
              </v-card-title><br>
              <v-card-text>
                <v-form @submit.prevent="submitForm">
                  <v-text-field
                    v-model="adminData.email"
                    label="Email"
                    outlined
                    required
                    rounded
                  ></v-text-field>
                  <v-text-field
                    v-model="adminData.password"
                    label="Password"
                    outlined
                    type="password"
                    required
                    rounded
                  ></v-text-field>
                  <v-btn color="green" :large="$vuetify.breakpoint.smAndUp" type="submit">
                    <v-icon left>lock</v-icon>
                    Login
                  </v-btn>
                </v-form>
                <v-alert
                  v-if="message"
                  :type="messageType"
                  dismissible
                  class="mt-4"
                >
                  {{ message }}
                </v-alert>
              </v-card-text>
            </v-card>
          </v-col>
        </v-row>
      </v-container>
    </v-app>
  </div>
</template>
<script>
import Navbar from "../components/NavbarComponent";
import jwt_decode from "jwt-decode";

export default {
  name: "AdminLogin",
  data() {
    return {
      adminData: {
        email: "",
        password: "",
      },
      message: "",
      messageType: "",
    };
  },
  components: {
    Navbar,

  },
  methods: {
    async submitForm() {
      try {
        this.message = ''; 
        this.messageType = '';
        this.loading = true; 
        const response = await fetch("http://localhost:5000/admin/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(this.adminData),
        });

        if (!response.ok) {
          throw new Error("Login failed");
        }

        const adminData = await response.json();
        var decoded = jwt_decode(adminData.access_token);
        localStorage.setItem("token", adminData.access_token);
        localStorage.setItem("username", decoded.sub.username);
        localStorage.setItem("role", decoded.sub.role);
        this.message = "Login successful";
        this.messageType = "success";
        this.$router.push({ name: "AdminDash" });
        this.$router.go();
      } catch (error) {
        console.error(error);
        this.message = "Login failed. Please check your credentials.";
        this.messageType = "error";
      }finally {
      this.loading = false; 
    }
    },
  },
};
</script>
<style scoped>
.background-image {
  border-radius: 25px;
  background-image: url('../assets/admin-login-background.jpg');
  background-size: cover;
  background-repeat: no-repeat;
  background-attachment: fixed;
  min-height: 100vh;
}

.card-background {
  background-color: rgba(255, 255, 255, 0.8);
}

.green--text {
  color: green;
}
</style>