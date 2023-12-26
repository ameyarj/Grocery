<template>
  <v-row justify="center" class="space px-16">
    <v-col
      cols="12"
      xs="12"
      sm="6"
      md="4"
      v-for="(product, index) in products"
      :key="index"
    >
      <v-card class="mx-auto rounded-xl" max-width="300" color="" flat outlined>
        <div align="center" justify="center">
          <v-img
            max-height="300"
            max-width="300"
            contain
            :src="getImageURL(product)"
          ></v-img>
        </div>

        <v-card-title class="">{{ product.name }}</v-card-title>
        <v-card-title class="grey--text text-grey-darken-1 caption mt-n6">{{
          product.description
        }}</v-card-title>
        <v-card-title class="grey--text text-grey-darken-1 caption mt-n6">Total Quantity:{{
          product.quantity
        }}</v-card-title>
        <v-card-title class="mt-n4">₹{{ product.price }}</v-card-title>

        <v-card-actions class="mx-2 mt-n4">
          <v-btn outlined class="mt-n2 add" @click="decrement(index)">
            <v-icon color="green" > mdi-minus </v-icon>
          </v-btn>

          <strong class="mx-2" v-text="product.count"></strong>

          
          <v-btn outlined class="mt-n2 add" @click="increment(index)">
            <v-icon color="green"> mdi-plus </v-icon>
          </v-btn>
          <v-spacer></v-spacer>
          <v-btn class="mx-2 mt-n3" fab dark small color="green" @click="addToCart(product)">
            <v-icon dark> mdi-shopping </v-icon>
          </v-btn>
          
        </v-card-actions>
      </v-card>
      <v-alert v-if="product.message" :type="product.messageType" dismissible class="mt-4" :key="index">
        {{ product.message }}
      </v-alert>

    </v-col>
  </v-row>
</template>

<script>
export default {
  data: () => ({
      
      products: [],
      message: "",
      messageType: "",
      plainCartItems: [],
     
  }),

  created() {
  this.fetchProducts();
  // this.fetchCartItems();
},

   methods: {
    async fetchProducts() {
    try {
      const response = await fetch("http://localhost:5000/api/products");
      if (response.ok) {
        const data = await response.json();
        this.products = data.map(product => ({
      ...product,
      count: 1,
      message: "",
    }));
      } else {
        console.error("Failed to fetch products:", response.status);

      }
    } catch (error) {
      console.error("An error occurred while fetching products:", error);
    }
  },
  async addToCart(product) {
try {
  const token = localStorage.getItem("token");
  if (!token) {
    this.message = "Unauthorized";
    this.messageType = "error";
    return;
  }
  
  console.log("Token:", token);
  
  const existingProduct = this.plainCartItems.find(item => item.product_id === product.id);
  
  if (existingProduct) {
    existingProduct.quantity += product.count;
  } else {
    const response = await fetch("http://localhost:5000/add-to-cart",{
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        product_id: product.id,
        product_name: product.name,
        product_image: product.image_filename,
        quantity: product.count,
        product_price: product.price,
      }),
    });
  
    if (response.ok) {
      product.message = "Added to Cart";
      product.messageType = "success";
      window.location.reload();
    } else {
      product.message = "Failed to add to cart";
      product.messageType = "error";
      console.error("Failed to add product to cart:", response.status);
      window.location.reload();

    }
  }
} catch (error) {
  product.message = "An error occurred while adding to the cart";
  product.messageType = "error";
  console.error("An error occurred while adding to the cart:", error);
  window.location.reload();

}
},

  getImageURL(product) {
    return product.image_filename || '';
  },
      
  decrement(index) {
if (this.products[index].count > 1) {
  this.products[index].count--;
}
},

increment(index) {
if (this.products[index].count < this.products[index].quantity) {
  this.products[index].count++;
}
},

}   
};
</script>

<style>
</style>