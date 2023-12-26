<template>
  <v-app-bar app color="white" flat>
    <v-badge color="#D5F0DB" dot>
      <v-img src="1.png" contain width="30"></v-img>
    </v-badge>

    <v-toolbar-title class="ml-4">
      <span class="green--text">e</span><strong>Grocery</strong>
    </v-toolbar-title>

    <v-spacer></v-spacer>
    <v-btn class="grey--text d-none d-sm-flex" text @click="goTo('/')"><strong>Home</strong></v-btn>
    <v-btn v-if="!isLoggedIn" class="grey--text d-none d-sm-flex" text @click="goTo('/UserLogin')"><strong>Login</strong></v-btn> 
    <v-btn v-if="!isLoggedIn" class="grey--text d-none d-sm-flex" text @click="goTo('/UserSignup')"><strong>Signup</strong></v-btn>
    <v-btn v-if="!isLoggedIn" class="grey--text d-none d-sm-flex" text @click="goTo('/AdminMain')"><strong>Admin</strong></v-btn>
    <v-btn v-if="showAdminDashboardButton" class="grey--text d-none d-sm-flex" text @click="goTo('/AdminDash')"><strong>Admin Dashboard</strong></v-btn>
    <v-btn v-if="showSmanagerDashboardButton" class="grey--text d-none d-sm-flex" text @click="goTo('/SmanagerDash')"><strong>Store Manager Dashboard</strong></v-btn>

    <v-btn v-if="isLoggedIn" class="grey--text d-none d-sm-flex" text @click="logout"><strong>Logout</strong></v-btn>

    <!-- <v-badge color="#FF6D59" overlap content="2" class="mr-2 mt-1">
      <v-avatar color="#FFF0EE" size="40">
        <v-icon x-small color="#FF6D59">far fa-heart</v-icon>
      </v-avatar>
    </v-badge> -->
    <v-badge v-if="showCartBadge" color="#41AB55" overlap class="mr-2 mt-1">
      <v-avatar color="#ECF7EE" size="40">
        <v-icon x-small color="#41AB55" @click="showCart">fas fa-shopping-cart</v-icon>
      </v-avatar>
    </v-badge>


    <cart-dialog ref="cartDialog" :plain-cart-items="plainCartItems" @clear-cart="clearCart" @update:plainCartItems="updatePlainCartItems"></cart-dialog>

    <span v-if="isLoggedIn" class="grey--text d-none d-sm-flex">Hello!<strong class="username">{{ getUsername().toUpperCase() }}</strong></span>

    <v-avatar v-if="isLoggedIn" size="30" class="ml-2" color="green" style="color: white;">
      <span class="text-h5">{{getUsername().charAt(0).toUpperCase()}}</span>
    </v-avatar>
    <v-menu offset-y v-if="showDropDown">
  <template v-slot:activator="{ on }">
    <v-btn icon dark v-on="on">
      <v-icon x-small color="#878A94">fas fa-chevron-down</v-icon>
    </v-btn>
  </template>
  <v-list>
    <v-list-item @click="goToPurchaseHistory">
      <v-list-item-title>Purchase History</v-list-item-title>
    </v-list-item>
    <v-list-item @click="goToUserSettings">
      <v-list-item-title>User Settings</v-list-item-title>
    </v-list-item>
  </v-list>
</v-menu>
  </v-app-bar>
</template>

<script>
import CartDialog from "../components/CartDialog.vue";
export default {
  data() {
    return {
      isLoggedIn: localStorage.getItem("token") !== null,
      username: localStorage.getItem("username") || "", 
      role: localStorage.getItem("role") || "",
      plainCartItems: [],
    };
  },
  components: {
    CartDialog,
  },
  computed: {
    showAdminDashboardButton() {
      const showButton = this.isLoggedIn && this.role === "admin";
      return showButton;
    },
    showSmanagerDashboardButton() {
      const showButton = this.isLoggedIn && this.role === "store_manager";
      return showButton;
    },
    showCartBadge(){
      const showButton = this.isLoggedIn && this.role !== "admin" && this.role !=="store_manager" ;
      return showButton;
    },
    showDropDown(){
      const showButton = this.isLoggedIn && this.role !== "admin" && this.role !=="store_manager";
      return showButton;
    }
  },
 
  created() {
    this.fetchCartItems();
  },
  methods: {
    async fetchCartItems() {
      try {
        const token = localStorage.getItem("token");
        if (!token) {
          this.plainCartItems = [];
          return;
        }
        const response = await fetch("http://localhost:5000/get-cart", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`,
          },
        });

        if (response.ok) {
          const data = await response.json();
          this.plainCartItems = data.map(item => ({ ...item }));
          console.log("Fetched cart items:", this.plainCartItems);
        } else {
          console.error("Failed to fetch cart items:", response.status);
        }
      } catch (error) {
        console.error("An error occurred while fetching cart items:", error);
      }
    },
    goTo(route) {
      this.$router.push(route);
      this.$router.go();
    },
    goToPurchaseHistory() {
    this.$router.push("/PurchaseHistory"); 
    this.$router.go();
  },
  goToUserSettings() {
    this.$router.push("/UserSettings");
    this.$router.go();
  },
    logout() {
      localStorage.removeItem("token");
      localStorage.removeItem("username"); 
      this.isLoggedIn = false;
      this.plainCartItems = [];


      if (this.$route.name !== "home") {
        this.$router.push({ name: "home" });
        this.$router.go();
      }
      window.location.reload();
    },
    getUsername() {
      return this.username;
    },
    showCart() {
      this.$refs.cartDialog.dialog = true;
    },
    clearCart() {
      this.plainCartItems = [];
      this.$refs.cartDialog.$emit("clear-cart"); 
     },
     updatePlainCartItems(updatedCartItems) {
    this.plainCartItems = updatedCartItems;
  },
},
};
</script>

<style>
.v-toolbar__title {
  font-size: 1rem !important;
}
.username {
  margin-left: 6px; 
}
</style>
