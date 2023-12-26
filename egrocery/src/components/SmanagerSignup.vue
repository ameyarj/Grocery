<template>
  <div>
    <Navbar />
    <v-app class="background-image">
      <v-container fill-height>
        <v-row justify="center" align="center">
          <v-col cols="12" sm="8" md="6">
            <v-card class="elevation-12 card-background mx-auto rounded-xl">
              <v-card-title class="darken-2 green--text justify-center">
                <h2 class="mb-0">Store Manager Signup</h2>
              </v-card-title>
              <br />
              <v-card-text>
                <v-form @submit.prevent="submitForm">
                  <v-text-field
                    v-model="storeManagerData.username"
                    label="Username"
                    outlined
                    required
                    rounded
                  ></v-text-field>

                  <v-text-field
                    v-model="storeManagerData.email"
                    label="Email"
                    outlined
                    required
                    rounded
                  ></v-text-field>

                  <v-text-field
                    v-model="storeManagerData.password"
                    label="Password"
                    type="password"
                    outlined
                    required
                    rounded
                  ></v-text-field>

                  <v-btn color="green" :large="$vuetify.breakpoint.smAndUp" type="submit">
                    <v-icon left>lock</v-icon>
                    Signup
                  </v-btn>
                </v-form>

                <v-alert v-if="signupSuccess" type="success" dismissible class="mt-4">
                  Signup successful! Your request is pending approval.
                  <router-link to="/AdminMain">Go to Main Page</router-link>.
                </v-alert>

                <v-alert v-if="signupError" type="error" dismissible class="mt-4">
                  {{ signupError }}
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

export default {
  name: "StoreManagerSignup",
  data: () => ({
    storeManagerData: {
      username: "",
      email: "",
      password: "",
    },
    signupSuccess: false,
    signupError: null,
  }),
  components: {
    Navbar,
  },
  methods: {
    submitForm() {
      fetch("http://localhost:5000/store-manager/signup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(this.storeManagerData),
      })

        .then(async (response) => {
          if (response.ok) {
            console.log(response)
            localStorage.setItem("username", this.storeManagerData.username);

            this.signupSuccess = true;
            this.signupError = null;
            console.log(this.signupSuccess)
          } else {
            this.signupSuccess = false;
            const data = await response.json();
this.signupError = data.error;
          }
        })
        .catch((error) => {
          console.error(error);
        });
    },
  },
};
</script>
<style scoped>
.background-image {
  border-radius: 25px;
  background-image: url('../assets/sm3.jpg');
  background-size: cover;
  background-repeat: no-repeat;
  background-attachment: fixed;
  min-height: 100vh;
}

.card-background {
  background-color: rgba(255, 255, 255, 0.8);
}
</style>

