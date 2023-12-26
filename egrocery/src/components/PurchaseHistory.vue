<template>
    <div>
        <Navbar/>
      <h1 class="mb-4">Purchase History</h1>
      <v-progress-linear v-if="loading" indeterminate color="primary"></v-progress-linear>
      <v-card v-else>
        <v-card-text v-if="purchaseHistory.length === 0">
          <p>No purchase history available.</p>
        </v-card-text>
        <v-data-table v-else :items="purchaseHistory" :headers="headers">
          <template v-slot:items="props">
            <td>{{ props.item.product_name }}</td>
            <td>{{ props.item.product_price }}</td>
            <td>{{ props.item.quantity }}</td>
            <td>{{ props.item.purchase_date }}</td>
          </template>
        </v-data-table>
      </v-card>
    </div>
  </template>
  
  <script>
import Navbar from "../components/NavbarComponent";

  export default {
    data() {
      return {
        purchaseHistory: [],
        loading: true,
        headers: [
          { text: 'Product Name', value: 'product_name' },
          { text: 'Product Price', value: 'product_price' },
          { text: 'Quantity', value: 'quantity' },
          { text: 'Purchase Date', value: 'purchase_date' },
        ],
      };
    },
    components:{
        Navbar,
    },
    created() {
      this.fetchPurchaseHistory();
    },
    methods: {
      async fetchPurchaseHistory() {
        try {
          const token = localStorage.getItem('token');
          if (!token) {
            this.loading = false;
            return;
          }
  
          const tokenPayload = JSON.parse(atob(token.split('.')[1]));
          const username = tokenPayload.username;
          const response = await fetch(`http://localhost:5000/purchase-history/${username}`, {
            method: 'GET',
            headers: {
              Authorization: `Bearer ${token}`,
            },
          });
  
          if (response.ok) {
            const data = await response.json();
            this.purchaseHistory = data;
          } else {
            console.error('Failed to fetch purchase history:', response.status);
          }
  
          this.loading = false;
        } catch (error) {
          console.error('An error occurred while fetching purchase history:', error);
          this.loading = false;
        }
      },
    },
  };
  </script>

  <style>
  </style>
  