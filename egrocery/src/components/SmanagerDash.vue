<template>
    <div>
      <Navbar />
      <h2>Welcome to the Store Manager Dashboard</h2>
      <div>
        <canvas ref="stockChart"></canvas>
      </div>
      <div>
        <canvas ref="salesChart"></canvas>
      </div>
      <div class="category-actions">
        <h3>Actions:</h3>
        <v-container class="mt-4">
      <v-row>
        <v-col cols="12" sm="6" md="4">
          <v-card @click="goToAddProduct" class="text-center">
            <v-img src="add-category.png" max-height="auto"></v-img>
            <v-card-title class="mt-2 btn btn-success">Add Product</v-card-title>
          </v-card>
        </v-col>
        <v-col cols="12" sm="6" md="4">
          <v-card @click="goToEditProduct" class="text-center">
            <v-img src="edit-category.png" max-height="auto"></v-img>
            <v-card-title class="mt-2 btn btn-success">Edit Product</v-card-title>
          </v-card>
        </v-col>
        <v-col cols="12" sm="6" md="4">
          <v-card @click="openCategoryRequestDialog" class="text-center">
            <v-img src="request.jpg" max-height="auto"></v-img>
            <v-card-title class="mt-2 btn btn-success">Request Category</v-card-title>
          </v-card>
        </v-col>
      </v-row>
    </v-container>
    <v-btn @click="exportProducts">Export Products</v-btn>
    <div v-if="message" :class="messageType">
      {{ message }}
      <v-btn @click="clearMessage">Close</v-btn>
    </div>
          <v-dialog v-model="categoryDialog" max-width="600">
            <v-card>
              <v-card-title>Add Category Request</v-card-title>
              <v-card-text>
                <v-text-field v-model="categoryTitle" label="Category Title"></v-text-field>
                <v-text-field v-model="categoryDescription" label="Category Description"></v-text-field>
                <input type="file" id="image" accept="image/*" @change="handleImageUpload" />
              </v-card-text>
              <v-card-actions>
                <v-btn @click="submitCategoryRequest">Submit Request</v-btn>
                <v-btn @click="closeCategoryRequestDialog">Close</v-btn>
              </v-card-actions>
            </v-card>
            <v-alert v-if="message" :class="messageType" dismissible>{{ message }}</v-alert>
          </v-dialog>
          <v-btn @click="openMessageDialog">Send Message</v-btn>

          <v-dialog v-model="messageDialog" max-width="600">
            <v-card>
              <v-card-title>Send Message to Admin</v-card-title>
              <v-card-text>
                <v-text-field v-model="messageTitle" label="Message Title"></v-text-field>
                <v-textarea v-model="messageBody" label="Message Body"></v-textarea>
              </v-card-text>
              <v-card-actions>
                <v-btn @click="sendMessage">Send Message</v-btn>
                <v-btn @click="closeMessageDialog">Close</v-btn>
              </v-card-actions>
            </v-card>
          </v-dialog>

        </div>
      </div>
  </template>
  
  <script>
  import Navbar from "../components/NavbarComponent";
  import Chart from "chart.js/auto";

  export default {
    name: "StoreManagerDashboard",
    data() {
  return {
    categoryDialog: false,
    categoryTitle: "",
    categoryDescription: "",
    categoryImage: null,
    messageDialog: false, 
    messageTitle: "",
     messageBody: "",
    message: "",
    messageType: "",
  };
},
mounted() {
    this.fetchChartData();
  },

    components: {
      Navbar,
      
    },
    methods:{
      async fetchChartData() {
      try {
        const response = await fetch("http://localhost:5000/store-manager/chart-data", {
          method: "GET",
          headers: {
            Authorization: "Bearer " + localStorage.getItem("token"),
          },
        });

        if (response.ok) {
          const data = await response.json();
          const stockData = data.stockData;
          const salesData = data.salesData;

          this.createChart("stockChart", "Stock Chart", stockData);

          this.createChart("salesChart", "Sales Chart", salesData);
        } else {
          const errorMessage = await response.json();
          console.error("Error fetching chart data:", errorMessage);
        }
      } catch (error) {
        console.error("An error occurred:", error);
      }
    },
    createChart(canvasId, chartTitle, data) {
      const canvas = this.$refs[canvasId];

      new Chart(canvas.getContext("2d"), {
        type: "bar",
        data: {
          labels: data.labels,
          datasets: [
            {
              label: chartTitle,
              backgroundColor: "rgba(75, 192, 192, 0.2)",
              borderColor: "rgba(75, 192, 192, 1)",
              borderWidth: 1,
              data: data.values,
            },
          ],
        },
        options: {
          scales: {
            y: {
              beginAtZero: true,
            },
          },
          maintainAspectRatio: false,
          responsive: true,
          aspectRatio: 1.5,
        },
      });
    },
      goToAddProduct() {
      this.$router.push({ name: "AddProduct" });
      this.$router.go();
    },
    goToEditProduct() {
      this.$router.push({ name: "EditProduct" });
      this.$router.go();
    },
    openCategoryRequestDialog() {
    this.categoryDialog = true;
  },
  closeCategoryRequestDialog() {
    this.categoryDialog = false;
    window.location.reload();
  },
  openMessageDialog() {
    this.messageDialog = true;
  },

  closeMessageDialog() {
    this.messageDialog = false;
  },

  handleImageUpload(event) {
      const file = event.target.files[0];
      if (file) {
        this.categoryImage = file;
      }
    },
  
    async sendMessage() {
  try {
    const token = localStorage.getItem("token");
    const response = await fetch('http://localhost:5000/store-manager/send-message', {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json', 
      },
      body: JSON.stringify({
        title: this.messageTitle,
        body: this.messageBody,
      }),
    });

    if (response.ok) {
      this.messageDialog = false;
      this.message = "Message Sent Successfully!";
      this.messageType = "success";
    } else {
      const errorMessage = await response.json();
      console.error("Error sending message:", errorMessage);
      this.message = "Failed to send message";
      this.messageType = "error";
    }
  } catch (error) {
    console.error("An error occurred:", error);
    this.message = "Failed to send message";
    this.messageType = "error";
  }
},

async submitCategoryRequest() {
  try {
    const formData = new FormData();
    formData.append('title', this.categoryTitle);
    formData.append('description', this.categoryDescription);
    formData.append('image', this.categoryImage);

    const response = await fetch('http://localhost:5000/store-manager/request-category', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + localStorage.getItem('token'), 
      },
      body: formData, 
    });

    if (response.ok) {
      this.categoryDialog = false; 
      this.message = "Request Sent Successfully! Wait for the Approval";
      this.messageType = "success";
      window.location.reload();
    } else {
      const errorMessage = await response.json();
      if (errorMessage.error === 'Category with this title already exists') {
        this.message = "Category with this title already exists";
      } else {
        this.message = "Failed to make a request";
      }
      this.messageType = "error";
    }
  } catch (error) {
    console.error('An error occurred:', error);
    this.message = "Failed to make a request! Something is wrong";
    this.messageType = "error";    
  }
},
async exportProducts() {
      try {
        const response = await fetch("http://localhost:5000/store-manager/export-products", {
          method: "GET",
          headers: {
            Authorization: "Bearer " + localStorage.getItem("token"),
          },
        });

        if (response.ok) {
          const blob = await response.blob();
          const link = document.createElement('a');
          link.href = window.URL.createObjectURL(blob);
          link.download = 'product_export.csv';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
        } else {
          const errorMessage = await response.json();
          console.error("Error exporting products:", errorMessage);
          this.message = "Failed to export products";
          this.messageType = "error";
        }
      } catch (error) {
        console.error("An error occurred:", error);
        this.message = "Something went wrong";
        this.messageType = "error";
      }
    },
    clearMessage() {
      this.message = "";
      this.messageType = "";
    },
  },
};
  </script>
  