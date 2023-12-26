<template>
  <div>
    <Navbar />
    <div class="add-product">
      <h2>Add Product</h2>
      <form @submit.prevent="addProduct">
        <div class="form-group">
          <label for="title">Name:</label>
          <input
            v-model="product.name"
            type="text"
            id="title"
            class="form-control"
          />
        </div>
        <br />
        <div class="form-group">
          <label for="description">Description:</label>
          <textarea
            v-model="product.description"
            id="description"
            class="form-control"
          ></textarea>
        </div>
        <br />
        <div class="form-group">
          <label for="price">Price:</label>
          <input
            v-model="product.price"
            type="number"
            id="price"
            class="form-control"
          />
        </div>
        <div class="form-group">
          <label for="quantity">Quantity:</label>
          <input
            v-model="product.quantity"
            type="number"
            step=any
            id="quantity"
            class="form-control"
          />
        </div>
        <br />

        <br />
        <div class="form-group">
          <label for="category">Category:</label>
          <select v-model="selectedCategory" id="category" class="form-control">
            <option value="" disabled>Select a category</option>
            <option
              v-for="category in categories"
              :key="category.id"
              :value="category.id"
            >
              {{ category.title }}
            </option>
          </select>
        </div><br/>
        <div class="form-group">
          <label for="image">Image:</label>
          <input
            type="file"
            id="image"
            accept="image/*"
            @change="handleImageUpload"
          />
        </div>
        <div class="my-3">
          <button type="submit" class="btn btn-primary">Add</button>
        </div>
      </form>
      <div v-if="imagePreview" class="image-preview">
        <img :src="imagePreview" alt="Product Image" />
      </div>
      <div v-if="message" class="alert" :class="messageType">{{ message }}</div>
    </div>
  </div>
</template>

<script>
import Navbar from "../components/NavbarComponent";

export default {
  name: "AddProduct",
  data() {
    return {
      product: {
        name: "",
        description: "",
        price: "",
        quantity: "",
        image: null,
        categories: [], 
      },
      selectedCategory: "",
      imagePreview: null,
      message: "",
      messageType: "",
    };
  },
  components: {
    Navbar,
  },
  created() {
    this.fetchCategories();
  },
  methods: {
    async addProduct() {
      try {
        const token = localStorage.getItem("token");

        if (!this.product.name) {
          this.message = "Name is required.";
          this.messageType = "alert-danger";
          return;
        }

        const formData = new FormData();
        formData.append("name", this.product.name);
        formData.append("description", this.product.description);
        formData.append("price", this.product.price);
        formData.append("quantity", this.product.quantity);
        formData.append("category_id", this.selectedCategory);

        if (this.product.image) {
          formData.append("image", this.product.image, this.product.image.name);
        }

        const response = await fetch(
          "http://localhost:5000/store-manager/add-product",
          {
            method: "POST",
            headers: {
              Authorization: "Bearer " + token,
            },
            body: formData,
          }
        );

        if (response.ok) {
          this.message = "Product added successfully.";
          this.messageType = "alert-success";
          this.product.title = "";
          this.product.description = "";
          this.product.price = "";
          this.product.quantity = "";
          this.product.image = null;
          this.imagePreview = null;
          window.location.reload();

        } else {
          this.message = "Failed to add Product.";
          this.messageType = "alert-danger";
          console.error("Failed to add product:", response.status);
        }
      } catch (error) {
        console.error("An error occurred:", error);
      }
    },
    async fetchCategories() {
    try {
      const response = await fetch("http://localhost:5000/api/categories");
      if (response.ok) {
        this.categories = await response.json();
      } else {
        console.error("Failed to fetch categories:", response.status);
      }
    } catch (error) {
      console.error("An error occurred while fetching categories:", error);
    }
  },
    handleImageUpload(event) {
      const file = event.target.files[0];
      if (file) {
        this.product.image = file;
      }
    },
  },
  beforeRouteEnter(to, from, next) {
    const token = localStorage.getItem("token");
    if (!token) {
      next({ name: "SmanagerDash" });
    } else {
      next();
    }
  },
};
</script>

<style>
.image-preview {
  margin-top: 10px;
  max-width: 100%;
  height: auto;
}
</style>
