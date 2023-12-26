<template>
  <div>
    <v-row justify="center" class="space px-16">
      <v-col
        cols="12"
        xs="12"
        sm="6"
        md="4"
        v-for="(product, index) in searchResults.products"
        :key="product.id"
      >
        <v-card class="mx-auto rounded-xl" max-width="300" color="" flat outlined>
          <div align="center" justify="center">
            <v-img
              max-height="300"
              max-width="300"
              contain
              :src="product.image_filename"
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
              <v-icon color="green">mdi-minus</v-icon>
            </v-btn>

            <strong class="mx-2">{{ searchResultsCopy.products[index].count }}</strong>

            <v-btn outlined class="mt-n2 add" @click="increment(index)">
              <v-icon color="green">mdi-plus</v-icon>
            </v-btn>
            <v-spacer></v-spacer>
            <v-btn class="mx-2 mt-n3" fab dark small color="green" @click="addToCart(product)">
              <v-icon dark>mdi-shopping</v-icon>
            </v-btn>
          </v-card-actions>
        </v-card>
      </v-col>
    </v-row>

    <v-item-group mandatory class="mt-n1">
      <v-container>
        <v-row justify="center" class="space">
          <v-col
            cols="12"
            xs="12"
            sm="4"
            md="2"
            v-for="(category) in searchResults.categories"
            :key="category.id"
          >
            <v-item v-slot="{ active, toggle }">
              <v-card
                :color="active ? '#D5F0DB' : 'white'"
                :class="active ? 'borderme' : 'borderout'"
                class="d-flex align-center rounded-lg mx-2"
                dark
                height="180"
                @click="toggle"
                flat
              >
                <v-row>
                  <v-col cols="12" sm="12">
                    <v-list-item three-line class="text-center">
                      <v-list-item-content>
                        <div align="center" justify="center">
                          <v-img
                            :src="category.image_filename"
                            max-height="80"
                            max-width="80"
                            contain
                          ></v-img>
                        </div>
                        <v-list-item-subtitle
                          :class="active ? 'green--text' : 'black--text'"
                          class="caption mt-4"
                        >
                          {{ category.title }}
                        </v-list-item-subtitle>
                      </v-list-item-content>
                    </v-list-item>
                    
                  </v-col>
                </v-row>
              </v-card>
            </v-item>
          </v-col>
        </v-row>
      </v-container>
    </v-item-group>
    <v-alert v-show="message" :type="messageType" dismissible class="mt-4">
      {{ message }}
    </v-alert>
    <v-alert v-if="noResultsMessage" :type="messageType" dismissible class="mt-4">
      {{ message }}
    </v-alert>
    <div >
      <p>No result</p>
    </div>

  </div>
</template>

<script>
export default {
  props: {
    searchQuery: String,
    searchResults: Object,
  },
  data() {
  return {
    products: this.initializeProductCounts(this.searchResults.products),
    categories: [...this.searchResults.categories],

    searchResultsCopy: { ...this.searchResults },
    plainCartItems: [],
    message: "",
    messageType: "",
  };
},
computed: {
    noResultsMessage() {
      const noProducts = !this.searchResultsCopy.products.length;
      const noCategories = !this.searchResultsCopy.categories.length;
      const noResults = noProducts && noCategories;
      
      return noResults;
    },
  },

created() {
  if (this.noResultsMessage) {
      this.message = "No results found";
      this.messageType = "info";
    }
console.log("searchResults in SearchResult.vue:", this.searchResults);

this.searchResultsCopy.products.forEach(product => {
  this.$set(product, 'count', 1);
});
},
methods: {
  initializeProductCounts(products) {
    return products.map(product => ({
      ...product,
      count: 1,
    }));
  },
  decrement(index) {
    if (this.searchResultsCopy.products[index].count > 1) {
      this.searchResultsCopy.products[index].count--;
    }
    console.log("Decrement clicked. New count:", this.searchResultsCopy.products[index].count);
  },
  increment(index) {
    const product = this.searchResultsCopy.products[index];
    if (product.count < product.quantity) {
      product.count++;
    }
    console.log("Increment clicked. New count:", this.searchResultsCopy.products[index].count);
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
      this.message = "Added to Cart";
      this.messageType = "success";
      window.location.reload();

    } else {
      this.message = "Failed to add to cart";
      this.messageType = "error";
      console.error("Failed to add product to cart:", response.status);
      window.location.reload();

    }
  }
} catch (error) {
  this.message = "An error occurred while adding to the cart";
  this.messageType = "error";
  console.error("An error occurred while adding to the cart:", error);
  window.location.reload();

}
},

},
};
</script>
<style scoped>
</style>
